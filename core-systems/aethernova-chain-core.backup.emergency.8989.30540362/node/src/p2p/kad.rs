// Path: aethernova-chain-core/node/src/p2p/kad.rs
//! Kademlia DHT service for Aethernova node.
//!
//! Design goals:
//! - Safe, composable API (command/event channels).
//! - Industrial defaults (Noise + Yamux over Tokio TCP; Identify + Kademlia).
//! - Bootstrap helpers (add known peers, dial, bootstrap).
//! - DHT primitives: put/get record; start_providing/get_providers.
//!
//! Rust libp2p references (see README/docs in repository and docs.rs):
//! - Kademlia behaviour & query results. :contentReference[oaicite:1]{index=1}
//! - Identify behaviour. :contentReference[oaicite:2]{index=2}
//! - Transport building (TCP + Noise + Yamux). :contentReference[oaicite:3]{index=3}
//! - Swarm overview. :contentReference[oaicite:4]{index=4}

use std::{num::NonZeroUsize, time::Duration};

use futures::{prelude::*, stream::StreamExt};
use libp2p::{
    core::upgrade::Version,
    identify,
    identity,
    kad::{
        self,
        store::MemoryStore,
        Behaviour as KadBehaviour,
        Config as KadConfig,
        GetProvidersOk,
        GetRecordOk,
        ProgressStep,
        ProviderRecord,
        PutRecordOk,
        Quorum,
        QueryResult,
        Record,
        RecordKey,
    },
    multiaddr::Protocol,
    noise,
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent, ToSwarm},
    tcp, yamux, Multiaddr, PeerId,
};
use tokio::sync::mpsc;

/// Commands accepted by Kademlia service.
#[derive(Debug)]
pub enum KadCommand {
    /// Add a known peer address.
    /// The `Multiaddr` may include `/p2p/<peerid>`; it will be split automatically.
    AddPeer { addr: Multiaddr },

    /// Add a bootstrap peer with explicit parts.
    AddAddress { peer: PeerId, addr: Multiaddr },

    /// Dial an address (may or may not be in routing table).
    Dial(Multiaddr),

    /// Trigger Kademlia bootstrap (self-lookup + bucket refresh).
    Bootstrap,

    /// Put a DHT record with quorum (quorum=None -> Quorum::One).
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        quorum: Option<NonZeroUsize>,
    },

    /// Get a DHT record with quorum (quorum=None -> Quorum::One).
    GetRecord {
        key: Vec<u8>,
        quorum: Option<NonZeroUsize>,
    },

    /// Announce this node as provider for a content key.
    StartProviding { key: Vec<u8> },

    /// Find providers for a content key.
    GetProviders { key: Vec<u8> },
}

/// Events emitted by the service (downstream to the node).
#[derive(Debug, Clone)]
pub enum KadEvent {
    BootstrapOk,
    BootstrapErr(String),

    PutOk { key: Vec<u8> },
    PutErr { key: Vec<u8>, err: String },

    GetOk { key: Vec<u8>, records: Vec<Vec<u8>> },
    GetErr { key: Vec<u8>, err: String },

    StartProvidingOk { key: Vec<u8> },
    StartProvidingErr { key: Vec<u8>, err: String },

    Providers { key: Vec<u8>, providers: Vec<PeerId> },

    /// Informational routing / progress signals.
    RoutingUpdated { peer: PeerId },
    QueryProgress { step: String },
    Dialed(Multiaddr),
    ListenAddr(Multiaddr),
}

/// Handle to interact with the running service.
pub struct KadHandle {
    pub peer_id: PeerId,
    cmd_tx: mpsc::Sender<KadCommand>,
    pub events: mpsc::Receiver<KadEvent>,
}

impl KadHandle {
    pub async fn send(&self, cmd: KadCommand) -> Result<(), mpsc::error::SendError<KadCommand>> {
        self.cmd_tx.send(cmd).await
    }
}

/// Public entry: spawn the Kademlia service on a background task.
pub async fn spawn(
    local_key: identity::Keypair,
    listen_addrs: Vec<Multiaddr>,
) -> anyhow::Result<KadHandle> {
    let peer_id = PeerId::from(local_key.public());
    let (mut swarm, mut behaviour) = build_swarm(local_key.clone())?;

    // Listen on requested addresses.
    for addr in listen_addrs {
        swarm.listen_on(addr.clone())?;
    }

    // Channels.
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<KadCommand>(256);
    let (evt_tx, evt_rx) = mpsc::channel::<KadEvent>(512);

    // Spawn the main loop.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Incoming commands from the node / other subsystems.
                maybe_cmd = cmd_rx.recv() => {
                    match maybe_cmd {
                        None => break, // handle dropped
                        Some(cmd) => {
                            if let Err(e) = handle_command(&mut swarm, &mut behaviour, cmd).await {
                                // Emit a generic error as progress note.
                                let _ = evt_tx.send(KadEvent::QueryProgress { step: format!("command error: {e}") }).await;
                            }
                        }
                    }
                }

                // Swarm events from the network.
                Some(event) = swarm.next() => {
                    match event {
                        SwarmEvent::Behaviour(CompositeEvent::Kad(kad_ev)) => {
                            // Map Kademlia events to KadEvent.
                            use kad::Event;
                            match kad_ev {
                                Event::QueryResult { result, .. } => {
                                    match result {
                                        QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
                                            let _ = evt_tx.send(KadEvent::PutOk { key: key.to_vec() }).await;
                                        }
                                        QueryResult::PutRecord(Err(e)) => {
                                            let key = e.key().to_vec();
                                            let _ = evt_tx.send(KadEvent::PutErr { key, err: format!("{e:?}") }).await;
                                        }
                                        QueryResult::GetRecord(Ok(GetRecordOk { records, .. })) => {
                                            // Collect values from returned records.
                                            let mut vals = Vec::new();
                                            let mut key = Vec::new();
                                            for kad::PeerRecord { record, .. } in records {
                                                if key.is_empty() { key = record.key.to_vec(); }
                                                vals.push(record.value);
                                            }
                                            let _ = evt_tx.send(KadEvent::GetOk { key, records: vals }).await;
                                        }
                                        QueryResult::GetRecord(Err(e)) => {
                                            // Query error exposes key via Display in most cases; keep message only.
                                            let _ = evt_tx.send(KadEvent::GetErr { key: Vec::new(), err: format!("{e:?}") }).await;
                                        }
                                        QueryResult::StartProviding(Ok(k)) => {
                                            let _ = evt_tx.send(KadEvent::StartProvidingOk { key: k.to_vec() }).await;
                                        }
                                        QueryResult::StartProviding(Err(e)) => {
                                            let _ = evt_tx.send(KadEvent::StartProvidingErr { key: e.key().to_vec(), err: format!("{e:?}") }).await;
                                        }
                                        QueryResult::GetProviders(Ok(GetProvidersOk { providers, key, .. })) => {
                                            let _ = evt_tx.send(KadEvent::Providers { key: key.to_vec(), providers: providers.into_iter().collect() }).await;
                                        }
                                        QueryResult::Bootstrap(Ok(_)) => {
                                            let _ = evt_tx.send(KadEvent::BootstrapOk).await;
                                        }
                                        QueryResult::Bootstrap(Err(e)) => {
                                            let _ = evt_tx.send(KadEvent::BootstrapErr(format!("{e:?}"))).await;
                                        }
                                        other => {
                                            // Other query results are informational.
                                            let _ = evt_tx.send(KadEvent::QueryProgress { step: format!("other: {other:?}") }).await;
                                        }
                                    }
                                }
                                Event::RoutingUpdated { peer, .. } => {
                                    let _ = evt_tx.send(KadEvent::RoutingUpdated { peer }).await;
                                }
                                Event::OutboundQueryProgressed { step, .. } => {
                                    let label = match step {
                                        ProgressStep::First => "first",
                                        ProgressStep::Last => "last",
                                        _ => "progress",
                                    };
                                    let _ = evt_tx.send(KadEvent::QueryProgress { step: label.to_string() }).await;
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let _ = evt_tx.send(KadEvent::ListenAddr(address)).await;
                        }
                        SwarmEvent::OutgoingConnectionEstablished { .. } => { /* noisy */ }
                        SwarmEvent::Dialing { address, .. } => {
                            let _ = evt_tx.send(KadEvent::Dialed(address)).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(KadHandle {
        peer_id,
        cmd_tx,
        events: evt_rx,
    })
}

/// Build Swarm and initial behaviour set.
fn build_swarm(
    local_key: identity::Keypair,
) -> anyhow::Result<(Swarm<CompositeBehaviour>, CompositeBehaviour)> {
    // Transport: TCP (tokio) + Noise(XX) + Yamux. :contentReference[oaicite:5]{index=5}
    let transport = tcp::tokio::Transport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .boxed();

    let local_peer_id = PeerId::from(local_key.public());

    // Identify behaviour to exchange peer info. :contentReference[oaicite:6]{index=6}
    let identify = identify::Behaviour::new(identify::Config::new(
        format!("aethernova-node/{}", env!("CARGO_PKG_VERSION")),
        local_key.public(),
    ));

    // Kademlia with in-memory record store.
    // MemoryStore implements local record/provide storage. :contentReference[oaicite:7]{index=7}
    let mut kad_cfg = KadConfig::default();
    kad_cfg.set_query_timeout(Duration::from_secs(60));
    // Доп. параметры (репликация/кэш) доступны через KadConfig.* (см. docs). :contentReference[oaicite:8]{index=8}

    let store = MemoryStore::new(local_peer_id);
    let kad = KadBehaviour::with_config(local_peer_id, store, kad_cfg);

    let behaviour = CompositeBehaviour { identify, kad };

    // Swarm.
    let swarm = SwarmBuilder::with_executor(transport, behaviour.clone(), local_peer_id, Box::new(|fut| {
        // Use tokio as executor.
        tokio::spawn(fut);
    }))
    .build();

    Ok((swarm, behaviour))
}

/// The combined behaviour for the node (Identify + Kademlia).
#[derive(NetworkBehaviour, Clone)]
#[behaviour(to_swarm = "CompositeEvent")]
struct CompositeBehaviour {
    identify: identify::Behaviour,
    kad: KadBehaviour<MemoryStore>,
}

/// Events emitted by the composite behaviour (wrapping member events). :contentReference[oaicite:9]{index=9}
#[derive(Debug)]
enum CompositeEvent {
    Identify(identify::Event),
    Kad(<KadBehaviour<MemoryStore> as NetworkBehaviour>::ToSwarm),
}

async fn handle_command(
    swarm: &mut Swarm<CompositeBehaviour>,
    behaviour: &mut CompositeBehaviour,
    cmd: KadCommand,
) -> anyhow::Result<()> {
    match cmd {
        KadCommand::AddPeer { addr } => {
            if let Some((peer, base)) = split_p2p_multiaddr(addr) {
                behaviour.kad.add_address(&peer, base); // add to routing table. :contentReference[oaicite:10]{index=10}
            }
        }
        KadCommand::AddAddress { peer, addr } => {
            behaviour.kad.add_address(&peer, addr); // explicit add. :contentReference[oaicite:11]{index=11}
        }
        KadCommand::Dial(addr) => {
            swarm.dial(addr)?;
        }
        KadCommand::Bootstrap => {
            behaviour.kad.bootstrap()?;
        }
        KadCommand::PutRecord { key, value, quorum } => {
            let k = RecordKey::new(&key); // opaque DHT key. :contentReference[oaicite:12]{index=12}
            let record = Record::new(k, value); // create DHT record. :contentReference[oaicite:13]{index=13}
            let q = quorum.map(Quorum::N).unwrap_or(Quorum::One);
            behaviour.kad.put_record(record, q)?;
        }
        KadCommand::GetRecord { key, quorum } => {
            let k = RecordKey::new(&key);
            let q = quorum.map(Quorum::N).unwrap_or(Quorum::One);
            behaviour.kad.get_record(k, q);
        }
        KadCommand::StartProviding { key } => {
            behaviour.kad.start_providing(RecordKey::new(&key))?;
        }
        KadCommand::GetProviders { key } => {
            behaviour.kad.get_providers(RecordKey::new(&key));
        }
    }
    Ok(())
}

/// If `addr` ends with `/p2p/<peer-id>` returns (peer, base_addr_without_p2p).
fn split_p2p_multiaddr(mut addr: Multiaddr) -> Option<(PeerId, Multiaddr)> {
    if let Some(Protocol::P2p(p2p_hash)) = addr.iter().last() {
        let _ = addr.pop();
        let peer = PeerId::from_multihash(p2p_hash).ok()?;
        Some((peer, addr))
    } else {
        None
    }
}
