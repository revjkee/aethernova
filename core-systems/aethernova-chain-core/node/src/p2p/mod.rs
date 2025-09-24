//! Aethernova P2P node module.
//!
//! Features:
//! - Secure transport: Noise XX over TCP, Yamux multiplexing.
//! - Behaviours: Gossipsub (pub/sub), Kademlia (DHT), Identify, Ping, Request/Response.
//! - Typed API: topics, publish/subscribe, DHT bootstrap, dial/add peer, request/response.
//! - Error model: thiserror-based, non-panicking.
//!
//! References:
//! - Noise XX in rust-libp2p (interop guarantee): https://docs.rs/libp2p/latest/libp2p/noise/  (*use XX*) 
//! - Gossipsub (pub/sub): https://docs.rs/libp2p/latest/libp2p/gossipsub/
//! - Kademlia (DHT): https://docs.rs/libp2p-kad
//! - Identify: https://docs.rs/libp2p/latest/libp2p/identify/
//! - Ping: https://docs.rs/libp2p-ping
//! - Request/Response: https://docs.rs/libp2p/latest/libp2p/request_response/
//! - Multiaddr: https://docs.rs/multiaddr

#![deny(rust_2018_idioms, unused_must_use, unreachable_pub)]
#![forbid(unsafe_code)]

use std::{collections::HashMap, time::Duration};

use futures::prelude::*;
use libp2p::{
    core::upgrade::Version,
    gossipsub::{
        self, IdentTopic as Topic, MessageId, ValidationMode,
        MessageAuthenticity,
    },
    identity,
    kad::{store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent, QueryId},
    multiaddr::Protocol,
    noise,
    ping::{self, Event as PingEvent, PingFailure, PingSuccess},
    request_response::{
        Behaviour as RequestResponse, Codec, Config as RRConfig, Event as RREvent, InboundRequest,
        Message as RRMessage, ProtocolSupport, RequestId, ResponseChannel,
    },
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent, derive_prelude::*},
    tcp,
    yamux, Multiaddr, PeerId, Transport,
};
use thiserror::Error;
use tokio::sync::mpsc;

/// Application-level request/response protocol constants.
pub const RR_PROTOCOL_NAME: &str = "/aethernova/reqres/1.0.0";
pub const IDENTIFY_PROTO: &str = "/aethernova/identify/1.0.0";
pub const AGENT_VERSION: &str = "aethernova-node/1";

/// Simple binary request/response.
#[derive(Debug, Clone)]
pub struct AppRequest(pub Vec<u8>);
#[derive(Debug, Clone)]
pub struct AppResponse(pub Vec<u8>);

/// Minimal codec: raw length-delimited bytes.
#[derive(Clone, Default)]
pub struct AppCodec;

#[async_trait::async_trait]
impl Codec for AppCodec {
    type Protocol = AppProtocol;
    type Request = AppRequest;
    type Response = AppResponse;

    async fn read_request<T>(&mut self, _: &AppProtocol, io: &mut T) -> std::io::Result<AppRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(AppRequest(buf))
    }

    async fn read_response<T>(
        &mut self,
        _: &AppProtocol,
        io: &mut T,
    ) -> std::io::Result<AppResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(AppResponse(buf))
    }

    async fn write_request<T>(
        &mut self,
        _: &AppProtocol,
        io: &mut T,
        AppRequest(data): AppRequest,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&(data.len() as u32).to_be_bytes()).await?;
        io.write_all(&data).await?;
        io.flush().await
    }

    async fn write_response<T>(
        &mut self,
        _: &AppProtocol,
        io: &mut T,
        AppResponse(data): AppResponse,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&(data.len() as u32).to_be_bytes()).await?;
        io.write_all(&data).await?;
        io.flush().await
    }
}

/// Protocol marker.
#[derive(Debug, Clone)]
pub struct AppProtocol;

impl libp2p::request_response::ProtocolName for AppProtocol {
    fn protocol_name(&self) -> &[u8] {
        RR_PROTOCOL_NAME.as_bytes()
    }
}

/// Unified behaviour for the node.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ComposedEvent")]
pub struct ComposedBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: libp2p::identify::Behaviour,
    pub ping: ping::Behaviour,
    pub reqres: RequestResponse<AppCodec>,
}

/// Unified event type emitted by behaviour.
#[derive(Debug)]
pub enum ComposedEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(KademliaEvent),
    Identify(libp2p::identify::Event),
    Ping(PingEvent),
    ReqRes(RREvent<AppRequest, AppResponse>),
}

impl From<gossipsub::Event> for ComposedEvent {
    fn from(e: gossipsub::Event) -> Self { Self::Gossipsub(e) }
}
impl From<KademliaEvent> for ComposedEvent {
    fn from(e: KademliaEvent) -> Self { Self::Kademlia(e) }
}
impl From<libp2p::identify::Event> for ComposedEvent {
    fn from(e: libp2p::identify::Event) -> Self { Self::Identify(e) }
}
impl From<PingEvent> for ComposedEvent {
    fn from(e: PingEvent) -> Self { Self::Ping(e) }
}
impl From<RREvent<AppRequest, AppResponse>> for ComposedEvent {
    fn from(e: RREvent<AppRequest, AppResponse>) -> Self { Self::ReqRes(e) }
}

/// Public node API.
pub struct Node {
    swarm: Swarm<ComposedBehaviour>,
    topics: HashMap<String, Topic>,
    /// Optional channel for incoming application requests (Request/Response).
    inbound_tx: Option<mpsc::Sender<(PeerId, AppRequest, ResponseChannel<AppResponse>)>>,
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("multiaddr parse error: {0}")]
    Addr(#[from] multiaddr::Error),
    #[error("swarm dial error: {0}")]
    Dial(String),
    #[error("publish failed")]
    Publish,
}

/// Builder parameters.
pub struct NodeConfig {
    pub keypair: identity::Keypair,
    pub gossip_validation: ValidationMode,
    pub gossip_validation_threads: usize,
    pub gossip_max_transmit_size: usize,
    pub kad_config: KademliaConfig,
    pub enable_req_res: bool,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            keypair: identity::Keypair::generate_ed25519(),
            gossip_validation: ValidationMode::Strict,
            gossip_validation_threads: 2,
            gossip_max_transmit_size: 1024 * 1024,
            kad_config: KademliaConfig::default(),
            enable_req_res: true,
            ping_interval: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(20),
        }
    }
}

impl Node {
    /// Create a new node with secure transport and composed behaviour.
    pub fn new(config: NodeConfig) -> anyhow::Result<Self> {
        let local_key = config.keypair;
        let local_peer_id = PeerId::from(local_key.public());

        // Transport: TCP + Noise(XX) + Yamux
        // Noise XX: only XX guarantees interop across libp2p implementations.
        // https://docs.rs/libp2p/latest/libp2p/noise/
        let noise_keypair = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&local_key)
            .expect("noise keypair");
        let transport = tcp::async_io::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(Version::V1Lazy)
            .authenticate(noise::Config::xx(noise_keypair))
            .multiplex(yamux::Config::default())
            .boxed();

        // Gossipsub with signed messages, strict validation.
        // https://docs.rs/libp2p/latest/libp2p/gossipsub/
        let message_auth = MessageAuthenticity::Signed(local_key.clone());
        let mut gs_config = gossipsub::ConfigBuilder::default()
            .validation_mode(config.gossip_validation)
            .validate_messages()
            .max_transmit_size(config.gossip_max_transmit_size)
            .build()
            .expect("gossipsub config");
        // Enable explicit ID function for deterministic MessageId.
        gs_config.message_id_fn = Some(ArcMessageId::default());

        let gossipsub = gossipsub::Behaviour::new(message_auth, gs_config)?;

        // Kademlia DHT
        // https://docs.rs/libp2p-kad
        let store = MemoryStore::new(local_peer_id);
        let kademlia = Kademlia::with_config(local_peer_id, store, config.kad_config);

        // Identify
        // https://docs.rs/libp2p/latest/libp2p/identify/
        let id_cfg = libp2p::identify::Config::new(IDENTIFY_PROTO.into(), local_key.public())
            .with_agent_version(AGENT_VERSION.into());
        let identify = libp2p::identify::Behaviour::new(id_cfg);

        // Ping
        // https://docs.rs/libp2p-ping
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(config.ping_interval)
                .with_timeout(config.ping_timeout)
                .with_keep_alive(true),
        );

        // Request/Response
        // https://docs.rs/libp2p/latest/libp2p/request_response/
        let rr = RequestResponse::new(
            AppCodec::default(),
            std::iter::once((AppProtocol, ProtocolSupport::Full)),
            RRConfig::default(),
        );

        let behaviour = ComposedBehaviour {
            gossipsub,
            kademlia,
            identify,
            ping,
            reqres: rr,
        };

        let swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

        Ok(Self {
            swarm,
            topics: HashMap::new(),
            inbound_tx: None,
        })
    }

    /// Get our PeerId.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Start listening on the given multiaddress (e.g. /ip4/0.0.0.0/tcp/0).
    pub fn listen_on(&mut self, addr: Multiaddr) -> anyhow::Result<()> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Dial a remote peer/multiaddress.
    pub fn dial(&mut self, mut addr: Multiaddr, peer: Option<PeerId>) -> Result<(), NodeError> {
        if let Some(p) = peer {
            if !addr.iter().any(|p2| matches!(p2, Protocol::P2p(_))) {
                addr.push(Protocol::P2p(p.into()));
            }
        }
        self.swarm.dial(addr).map_err(|e| NodeError::Dial(e.to_string()))
    }

    /// Add known peer address to Kademlia routing table.
    pub fn add_known_peer(&mut self, peer: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer, addr);
    }

    /// Bootstrap DHT.
    pub fn kad_bootstrap(&mut self) -> QueryId {
        self.swarm.behaviour_mut().kademlia.bootstrap().expect("bootstrap")
    }

    /// Subscribe to a Gossipsub topic (creates if not exists).
    pub fn subscribe(&mut self, topic_str: &str) -> anyhow::Result<Topic> {
        let topic = self
            .topics
            .entry(topic_str.to_owned())
            .or_insert_with(|| Topic::new(topic_str));
        self.swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        Ok(topic.clone())
    }

    /// Publish a message to a Gossipsub topic.
    pub fn publish(&mut self, topic: &Topic, data: impl Into<Vec<u8>>) -> Result<MessageId, NodeError> {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), data.into())
            .map_err(|_| NodeError::Publish)
    }

    /// Send an application request via Request/Response.
    pub fn send_request(&mut self, peer: &PeerId, data: Vec<u8>) -> RequestId {
        self.swarm
            .behaviour_mut()
            .reqres
            .send_request(peer, AppRequest(data))
    }

    /// Install a channel for inbound application requests.
    pub fn set_inbound_handler(
        &mut self,
        tx: mpsc::Sender<(PeerId, AppRequest, ResponseChannel<AppResponse>)>,
    ) {
        self.inbound_tx = Some(tx);
    }

    /// Drive the swarm until the next relevant event; returns Some for externally-interesting ones.
    pub async fn next_event(&mut self) -> Option<NodeEvent> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(ComposedEvent::Gossipsub(ev)) => {
                    if let gossipsub::Event::Message { message, .. } = ev {
                        return Some(NodeEvent::GossipMessage {
                            source: message.source,
                            topic: message.topic,
                            data: message.data,
                        });
                    }
                }
                SwarmEvent::Behaviour(ComposedEvent::ReqRes(ev)) => match ev {
                    RREvent::Message { peer, message } => match message {
                        RRMessage::Request {
                            request, channel, ..
                        } => {
                            if let Some(tx) = &self.inbound_tx {
                                let _ = tx.send((peer, request, channel)).await;
                            }
                        }
                        RRMessage::Response { request_id, response } => {
                            return Some(NodeEvent::RequestResponse { request_id, response });
                        }
                    },
                    _ => {}
                },
                SwarmEvent::Behaviour(ComposedEvent::Ping(PingEvent { result, .. })) => match result {
                    Ok(PingSuccess::Ping { rtt }) => {
                        return Some(NodeEvent::Ping { ok: true, rtt: Some(rtt) });
                    }
                    Ok(PingSuccess::Pong) => {}
                    Err(PingFailure::Timeout) | Err(PingFailure::Other { .. }) => {
                        return Some(NodeEvent::Ping { ok: false, rtt: None });
                    }
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Some(NodeEvent::NewListenAddr { addr: address });
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return Some(NodeEvent::PeerConnected { peer: peer_id });
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return Some(NodeEvent::PeerDisconnected { peer: peer_id });
                }
                _ => {}
            }
        }
    }
}

/// Public node events exposed to the application.
#[derive(Debug)]
pub enum NodeEvent {
    NewListenAddr { addr: Multiaddr },
    PeerConnected { peer: PeerId },
    PeerDisconnected { peer: PeerId },
    GossipMessage {
        source: Option<PeerId>,
        topic: TopicHash,
        data: Vec<u8>,
    },
    RequestResponse {
        request_id: RequestId,
        response: AppResponse,
    },
    Ping {
        ok: bool,
        rtt: Option<Duration>,
    },
}

// ------------- internal helpers -------------

use gossipsub::TopicHash;
use std::sync::Arc;

/// Deterministic MessageId based on content (useful for dedup).
#[derive(Clone, Default)]
struct ArcMessageId;
impl ArcMessageId {
    fn calc(data: &[u8]) -> MessageId {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        let out = h.finalize();
        MessageId::from(out[..20].to_vec())
    }
}

/// Replace gossipsub internal default with content-based id.
trait GossipConfigExt {
    fn message_id_fn(self) -> Self;
}
impl GossipConfigExt for gossipsub::Config {
    fn message_id_fn(mut self) -> Self {
        let f = |m: &gossipsub::GossipsubMessage| ArcMessageId::calc(&m.data);
        self.set_message_id_fn(f);
        self
    }
}
