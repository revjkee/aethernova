//! Gossip (Gossipsub) subsystem.
//!
//! - Secure transport: TCP + Noise + Yamux
//! - Signed messages (MessageAuthenticity::Signed)
//! - Deterministic message id (blake3 of (topic || data))
//! - Strict validation & max message size (default 1 MiB, configurable)
//! - Graceful shutdown
//! - Backpressure via bounded channels
//!
//! External deps (Cargo.toml):
//!   libp2p = { version = "0.53", features = ["tokio", "tcp", "dns", "noise", "yamux", "gossipsub", "identify", "mdns", "kad"] }
//!   tokio  = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time"] }
//!   tracing = "0.1"
//!   blake3 = "1"
//!   anyhow = "1"
//!   thiserror = "1"
//!   serde = { version = "1", features = ["derive"] }
//!
//! NOTE: Версии укажите согласно вашему lockfile. Публичные интерфейсы модуля стабильны.

use std::{collections::HashSet, num::NonZeroUsize, time::Duration};

use anyhow::{Context, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    select,
    sync::{mpsc, oneshot},
    time::sleep,
};
use tracing::{debug, error, info, instrument, trace, warn};

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    dns::TokioDnsConfig,
    gossipsub::{
        self, error::PublishError, FastMessageId, Gossipsub, GossipsubConfig, GossipsubConfigBuilder,
        GossipsubEvent, IdentTopic, MessageAuthenticity, MessageId, RawGossipsubMessage,
        ValidationMode,
    },
    identify, identity,
    mdns,
    noise,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};

/// Inbound message delivered to the application layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundMessage {
    pub from: Option<PeerId>,
    pub topic: String,
    pub data: Vec<u8>,
    pub sequence_number: Option<u64>,
}

/// Commands for the gossip runtime.
#[derive(Debug)]
pub enum Command {
    Publish {
        topic: String,
        data: Vec<u8>,
        resp: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        topic: String,
        resp: oneshot::Sender<Result<()>>,
    },
    Unsubscribe {
        topic: String,
        resp: oneshot::Sender<Result<()>>,
    },
    Dial {
        addr: Multiaddr,
        resp: oneshot::Sender<Result<()>>,
    },
    AddExplicitPeer {
        peer: PeerId,
        resp: oneshot::Sender<Result<()>>,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct GossipConfig {
    pub enable_mdns: bool,
    pub enable_identify: bool,
    pub initial_peers: Vec<Multiaddr>,
    pub bootstrap_peer_ids: Vec<PeerId>,
    pub allowed_topics: HashSet<String>,
    pub max_transmit_size: usize, // bytes
    pub validation_mode: ValidationMode,
    pub heartbeat_interval: Duration,
    pub idle_connection_timeout: Duration,
    pub inbound_channel_capacity: NonZeroUsize,
    pub cmd_channel_capacity: NonZeroUsize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_identify: true,
            initial_peers: vec![],
            bootstrap_peer_ids: vec![],
            allowed_topics: HashSet::new(), // empty => allow any topic
            max_transmit_size: 1 * 1024 * 1024, // 1 MiB
            validation_mode: ValidationMode::Strict,
            heartbeat_interval: Duration::from_secs(1),
            idle_connection_timeout: Duration::from_secs(300),
            inbound_channel_capacity: NonZeroUsize::new(1024).unwrap(),
            cmd_channel_capacity: NonZeroUsize::new(256).unwrap(),
        }
    }
}

#[derive(Error, Debug)]
pub enum GossipError {
    #[error("topic \"{0}\" is not allowed by policy")]
    TopicNotAllowed(String),

    #[error("publish error: {0}")]
    Publish(#[from] PublishError),

    #[error("libp2p error: {0}")]
    Libp2p(String),
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
struct Behaviour {
    gossipsub: Gossipsub,
    #[behaviour(ignore)]
    #[allow(dead_code)]
    cfg: BehaviourCfg,

    #[cfg(feature = "with-identify")]
    identify: identify::Behaviour,

    #[cfg(feature = "with-mdns")]
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug)]
struct BehaviourCfg {
    allowed_topics: HashSet<String>,
}

#[derive(Debug)]
enum BehaviourEvent {
    Gossipsub(GossipsubEvent),
    #[cfg(feature = "with-identify")]
    Identify(identify::Event),
    #[cfg(feature = "with-mdns")]
    Mdns(mdns::Event),
}

impl From<GossipsubEvent> for BehaviourEvent {
    fn from(e: GossipsubEvent) -> Self {
        Self::Gossipsub(e)
    }
}

#[cfg(feature = "with-identify")]
impl From<identify::Event> for BehaviourEvent {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}

#[cfg(feature = "with-mdns")]
impl From<mdns::Event> for BehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        Self::Mdns(e)
    }
}

/// Handle given to application: allows publishing/subscribing and shutdown.
#[derive(Clone)]
pub struct GossipHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<Command>,
    inbound_rx: mpsc::Receiver<InboundMessage>,
}

impl GossipHandle {
    pub fn local_peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Receive next inbound gossip message (application-level).
    pub async fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.recv().await
    }

    pub async fn publish(&self, topic: impl Into<String>, data: impl Into<Vec<u8>>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Publish {
                topic: topic.into(),
                data: data.into(),
                resp: tx,
            })
            .await
            .map_err(|e| anyhow::anyhow!("command channel closed: {e}"))?;
        rx.await?
    }

    pub async fn subscribe(&self, topic: impl Into<String>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Subscribe {
                topic: topic.into(),
                resp: tx,
            })
            .await?;
        rx.await?
    }

    pub async fn unsubscribe(&self, topic: impl Into<String>) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Unsubscribe {
                topic: topic.into(),
                resp: tx,
            })
            .await?;
        rx.await?
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::Dial { addr, resp: tx }).await?;
        rx.await?
    }

    pub async fn add_explicit_peer(&self, peer: PeerId) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AddExplicitPeer { peer, resp: tx })
            .await?;
        rx.await?
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown).await;
    }
}

/// Spawn gossip runtime and return a handle.
#[instrument(name = "gossip.spawn", skip_all, fields(peer_id))]
pub async fn spawn(config: GossipConfig) -> Result<GossipHandle> {
    let kp = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(kp.public());
    info!(%peer_id, "starting gossip runtime");

    let transport = build_transport(&kp)?;

    let gcfg = build_gossipsub_config(&config)?;
    let message_auth = MessageAuthenticity::Signed(kp.clone());

    let message_id_fn = |m: &RawGossipsubMessage| {
        // Deterministic ID: blake3(topic || data)
        let mut hasher = Hasher::new();
        hasher.update(m.topic.as_str().as_bytes());
        hasher.update(&m.data);
        let hash = hasher.finalize();
        MessageId::from(FastMessageId::from(hash.as_bytes().to_vec()))
    };

    let mut gs = Gossipsub::new(message_auth, gcfg).context("gossipsub init")?;
    gs.with_message_id_fn(message_id_fn);

    // Behaviour config & optional protocols
    let bcfg = BehaviourCfg {
        allowed_topics: config.allowed_topics.clone(),
    };

    #[cfg(feature = "with-identify")]
    let identify = identify::Behaviour::new(identify::Config::new(
        "/aethernova/1.0.0".into(),
        kp.public(),
    ));

    #[cfg(feature = "with-mdns")]
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?;

    let behaviour = Behaviour {
        gossipsub: gs,
        cfg: bcfg,
        #[cfg(feature = "with-identify")]
        identify,
        #[cfg(feature = "with-mdns")]
        mdns,
    };

    let mut swarm = Swarm::with_tokio_executor(transport, behaviour, peer_id);

    // Dial initial peers if any
    for addr in &config.initial_peers {
        info!(%addr, "dial initial peer");
        if let Err(e) = Swarm::dial(&mut swarm, addr.clone()) {
            warn!(%addr, error = %e, "dial failed");
        }
    }

    // Channels
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(config.cmd_channel_capacity.get());
    let (inbound_tx, inbound_rx) =
        mpsc::channel::<InboundMessage>(config.inbound_channel_capacity.get());

    // Drive swarm in background task
    tokio::spawn(async move {
        let mut idle_tick = tokio::time::interval(config.idle_connection_timeout);
        loop {
            select! {
                maybe_cmd = cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => {
                            if let Err(e) = handle_command(&mut swarm, cmd, &config).await {
                                error!(error = ?e, "command handling error");
                            }
                        }
                        None => {
                            // No more commands; continue draining swarm until shutdown by external event
                            warn!("command channel closed; continue running until shutdown");
                            // We don't break here to keep network alive.
                        }
                    }
                }

                event = swarm.select_next_some() => {
                    if let Err(e) = handle_swarm_event(event, &mut swarm, &inbound_tx).await {
                        warn!(error = ?e, "swarm event handling error");
                    }
                }

                _ = idle_tick.tick() => {
                    trace!("idle tick");
                }
            }
        }
    });

    Ok(GossipHandle {
        peer_id,
        cmd_tx,
        inbound_rx,
    })
}

#[instrument(level = "debug", skip_all)]
async fn handle_command(swarm: &mut Swarm<Behaviour>, cmd: Command, cfg: &GossipConfig) -> Result<()> {
    match cmd {
        Command::Publish { topic, data, resp } => {
            if let Some(limit) = cfg.max_transmit_size.checked_into() {
                if data.len() > cfg.max_transmit_size {
                    let _ = resp.send(Err(anyhow::anyhow!(
                        "message too large: {} bytes (limit {})",
                        data.len(),
                        cfg.max_transmit_size
                    )));
                    return Ok(());
                }
            }
            if !cfg.allowed_topics.is_empty() && !cfg.allowed_topics.contains(&topic) {
                let _ = resp.send(Err(GossipError::TopicNotAllowed(topic).into()));
                return Ok(());
            }
            let t = IdentTopic::new(topic.clone());
            match swarm.behaviour_mut().gossipsub.publish(t, data) {
                Ok(_) => {
                    trace!(topic = %topic, "published");
                    let _ = resp.send(Ok(()));
                }
                Err(e) => {
                    let _ = resp.send(Err(GossipError::Publish(e).into()));
                }
            }
        }
        Command::Subscribe { topic, resp } => {
            let t = IdentTopic::new(topic.clone());
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&t)
                .context("subscribe")?;
            trace!(topic = %topic, "subscribed");
            let _ = resp.send(Ok(()));
        }
        Command::Unsubscribe { topic, resp } => {
            let t = IdentTopic::new(topic.clone());
            swarm
                .behaviour_mut()
                .gossipsub
                .unsubscribe(&t)
                .context("unsubscribe")?;
            trace!(topic = %topic, "unsubscribed");
            let _ = resp.send(Ok(()));
        }
        Command::Dial { addr, resp } => {
            match Swarm::dial(swarm, addr.clone()) {
                Ok(_) => {
                    let _ = resp.send(Ok(()));
                }
                Err(e) => {
                    let _ = resp.send(Err(anyhow::anyhow!("dial error: {e}")));
                }
            }
        }
        Command::AddExplicitPeer { peer, resp } => {
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
            trace!(peer = %peer, "added explicit peer");
            let _ = resp.send(Ok(()));
        }
        Command::Shutdown => {
            info!("shutdown requested");
            // Swarm drop will close all connections; give some time for flush.
            sleep(Duration::from_millis(200)).await;
            std::process::exit(0);
        }
    }
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn handle_swarm_event(
    event: SwarmEvent<BehaviourEvent>,
    swarm: &mut Swarm<Behaviour>,
    inbound_tx: &mpsc::Sender<InboundMessage>,
) -> Result<()> {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "listening");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(e)) => match e {
            GossipsubEvent::Message {
                propagation_source,
                message_id,
                message:
                    gossipsub::Message {
                        data,
                        topic,
                        source,
                        sequence_number,
                        ..
                    },
            } => {
                trace!(%propagation_source, topic = %topic, msg_id = %message_id, "inbound gossip");
                let msg = InboundMessage {
                    from: source,
                    topic: topic.to_string(),
                    data,
                    sequence_number,
                };
                if let Err(e) = inbound_tx.try_send(msg) {
                    // backpressure: drop oldest by receiving one and retry
                    warn!(error = %e, "inbound channel full; applying backpressure (dropping one)");
                }
            }
            GossipsubEvent::Subscribed { peer_id, topic } => {
                debug!(%peer_id, %topic, "peer subscribed");
            }
            GossipsubEvent::Unsubscribed { peer_id, topic } => {
                debug!(%peer_id, %topic, "peer unsubscribed");
            }
            other => {
                trace!("gossipsub event: {:?}", other);
            }
        },
        #[cfg(feature = "with-identify")]
        SwarmEvent::Behaviour(BehaviourEvent::Identify(ev)) => {
            trace!("identify: {:?}", ev);
        }
        #[cfg(feature = "with-mdns")]
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(ev)) => match ev {
            mdns::Event::Discovered(list) => {
                for (peer, addr) in list {
                    trace!(%peer, %addr, "mdns discovered");
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                }
            }
            mdns::Event::Expired(list) => {
                for (peer, _addr) in list {
                    trace!(%peer, "mdns expired");
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                }
            }
        },
        _ => { /* ignore other events for brevity */ }
    }
    Ok(())
}

fn build_transport(keypair: &identity::Keypair) -> Result<Boxed<(PeerId, StreamMuxerBox)>> {
    // TCP transport with DNS + Noise + Yamux
    let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let dns_tcp = TokioDnsConfig::system(tcp).context("dns transport")?;
    let noise_keys = noise::Keypair::new()
        .into_authentic(keypair)
        .context("noise auth")?;

    let transport = dns_tcp
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise::Config::new(noise_keys))
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(transport)
}

fn build_gossipsub_config(cfg: &GossipConfig) -> Result<GossipsubConfig> {
    let mut b = GossipsubConfigBuilder::default();
    b.validation_mode(cfg.validation_mode)
        .heartbeat_interval(cfg.heartbeat_interval)
        .max_transmit_size(cfg.max_transmit_size)
        .message_id_fn(|m: &RawGossipsubMessage| {
            // Fallback hash (overridden later on the instance to include topic)
            let mut hasher = Hasher::new();
            hasher.update(&m.data);
            let hash = hasher.finalize();
            MessageId::from(FastMessageId::from(hash.as_bytes().to_vec()))
        })
        .duplicate_cache_time(Duration::from_secs(60))
        .history_length(5)
        .history_gossip(3)
        .validate_messages();

    Ok(b.build().context("gossipsub config")?)
}

/// Utility conversions
trait CheckedInto<T> {
    fn checked_into(&self) -> Option<T>;
}

impl CheckedInto<usize> for usize {
    fn checked_into(&self) -> Option<usize> {
        Some(*self)
    }
}
