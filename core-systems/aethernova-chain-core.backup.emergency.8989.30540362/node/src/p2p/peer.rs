//! Aethernova Chain Core - P2P Peer
//! Industrial-grade peer implementation with length-delimited framing,
//! serde-based messages, tracing, timeouts, graceful shutdown, and optional
//! Noise encryption (feature: "noise").
//!
//! Dependencies (Cargo.toml, indicative):
//! tokio = { version = "1", features = ["full"] }
//! tokio-util = { version = "0.7", features = ["codec"] }
//! bytes = "1"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! thiserror = "1"
//! tracing = "0.1"
//! rand = "0.8"
//! ed25519-dalek = { version = "2", features = ["rand_core"] }
//! snow = { version = "0.9", optional = true }
//!
//! Feature flags:
//! default = []
//! noise = ["snow"]
//!
//! References:
//! - TcpStream split/into_split: docs.rs/tokio/latest (tokio::net::TcpStream)  [see README / citations]
//! - LengthDelimitedCodec: docs.rs/tokio-util/latest                            [see README / citations]
//! - serde/serde_json, tracing, timeout, ed25519-dalek, snow                   [see README / citations]

use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    net::TcpStream,
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time::{interval, timeout, Instant},
};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[cfg(feature = "noise")]
use snow::{Builder as NoiseBuilder, params::NoiseParams};

// ----------------------------- Public Types ---------------------------------

/// Stable peer identifier based on ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct PeerId(pub [u8; 32]);

impl From<VerifyingKey> for PeerId {
    fn from(vk: VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

/// Config for a peer connection.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// Maximum single frame size (bytes) for LengthDelimitedCodec.
    pub max_frame_len: usize,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
    /// Read timeout for single frame (applied per receive).
    pub read_frame_timeout: Duration,
    /// Write timeout for single frame (applied per send).
    pub write_frame_timeout: Duration,
    /// Heartbeat interval (ping).
    pub heartbeat_interval: Duration,
    /// Disconnect peer if no frames received within this time.
    pub idle_disconnect: Duration,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            max_frame_len: 1024 * 1024,                // 1 MiB
            handshake_timeout: Duration::from_secs(5),
            read_frame_timeout: Duration::from_secs(15),
            write_frame_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(20),
            idle_disconnect: Duration::from_secs(60),
        }
    }
}

/// Outbound commands to a peer.
#[derive(Debug)]
pub enum PeerCommand {
    SendApp(Bytes),
    SendPing(u64),
    Close,
}

/// Inbound events from a peer to the upper layer.
#[derive(Debug)]
pub enum PeerEvent {
    HandshakeCompleted(PeerId, SocketAddr),
    Pong(u64),
    App(Bytes),
    Closed(Option<anyhow::Error>),
}

/// Public handle to interact with the running peer task.
#[derive(Clone)]
pub struct PeerHandle {
    peer_id: Option<PeerId>,
    remote: SocketAddr,
    cmd_tx: mpsc::Sender<PeerCommand>,
    shutdown_tx: broadcast::Sender<()>,
}

impl PeerHandle {
    pub fn peer_id(&self) -> Option<PeerId> { self.peer_id }
    pub fn remote_addr(&self) -> SocketAddr { self.remote }

    /// Enqueue application payload (already serialized) for sending.
    pub async fn send_app(&self, payload: Bytes) -> Result<(), SendError> {
        self.cmd_tx.send(PeerCommand::SendApp(payload))
            .await
            .map_err(|_| SendError::ChannelClosed)
    }

    /// Send ping with sequence number.
    pub async fn ping(&self, seq: u64) -> Result<(), SendError> {
        self.cmd_tx.send(PeerCommand::SendPing(seq))
            .await
            .map_err(|_| SendError::ChannelClosed)
    }

    /// Ask peer task to close gracefully.
    pub async fn close(&self) -> Result<(), SendError> {
        self.cmd_tx.send(PeerCommand::Close)
            .await
            .map_err(|_| SendError::ChannelClosed)
    }

    /// Broadcast a shutdown signal (used when closing multiple peers).
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("peer command channel closed")]
    ChannelClosed,
}

// ------------------------------ Wire Format ----------------------------------

/// Versioned protocol wrapper.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

pub const PROTOCOL_V1: ProtocolVersion = ProtocolVersion(1);

/// Wire message types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
enum WireMessage {
    /// Initial hello(handshake), carries peer public key for identity binding.
    Hello { version: ProtocolVersion, peer_pk: [u8; 32] },

    /// Ping/Pong control frames for liveness.
    Ping { seq: u64, at: u64 },
    Pong { seq: u64, at: u64 },

    /// Application payload (opaque bytes).
    App { data: #[serde(with = "serde_bytes")] Vec<u8> },
}

// ------------------------------ Crypto Layer ---------------------------------

#[derive(Clone)]
struct Identity {
    signing: Arc<SigningKey>,
    verifying: VerifyingKey,
    id: PeerId,
}

impl Identity {
    fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let id = PeerId::from(verifying);
        Self { signing: Arc::new(signing), verifying, id }
    }
}

#[cfg(feature = "noise")]
mod noise {
    use super::*;
    /// Simple Noise wrapper performing NNpsk0 or IX pattern handshake and then
    /// providing encrypt/decrypt helpers for application frames.
    pub struct NoiseChannel {
        session: snow::Session,
    }

    impl NoiseChannel {
        pub fn new_initiator() -> anyhow::Result<Self> {
            // NN (no static keys exchanged) is simplest to start with; you can
            // upgrade to IX or XX to bind static keys.
            // See docs.rs/snow and the Noise spec for details.
            let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse()?;
            let builder = snow::Builder::new(params);
            Ok(Self { session: builder.build_initiator()? })
        }
        pub fn new_responder() -> anyhow::Result<Self> {
            let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse()?;
            let builder = snow::Builder::new(params);
            Ok(Self { session: builder.build_responder()? })
        }
        pub fn is_handshake_finished(&self) -> bool {
            self.session.is_handshake_finished()
        }
        pub fn write_handshake_msg(&mut self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut out = vec![0u8; payload.len() + 1024];
            let n = self.session.write_message(payload, &mut out)?;
            out.truncate(n);
            Ok(out)
        }
        pub fn read_handshake_msg(&mut self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut out = vec![0u8; msg.len() + 1024];
            let n = self.session.read_message(msg, &mut out)?;
            out.truncate(n);
            Ok(out)
        }
        pub fn encrypt(&mut self, plain: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut out = vec![0u8; plain.len() + 16];
            let n = self.session.write_message(plain, &mut out)?;
            out.truncate(n);
            Ok(out)
        }
        pub fn decrypt(&mut self, cipher: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut out = vec![0u8; cipher.len()];
            let n = self.session.read_message(cipher, &mut out)?;
            out.truncate(n);
            Ok(out)
        }
    }
}

// ------------------------------- Peer Task -----------------------------------

enum Direction { Outbound, Inbound }

struct PeerCtx {
    cfg: PeerConfig,
    identity: Identity,
    remote: SocketAddr,
    direction: Direction,
}

pub struct Peer;

impl Peer {
    /// Dial an outbound connection and spawn the peer task.
    #[instrument(level = "info", skip(cfg))]
    pub async fn dial(
        remote: SocketAddr,
        cfg: PeerConfig,
        identity: Option<Identity>,
        events_tx: mpsc::Sender<PeerEvent>,
    ) -> anyhow::Result<PeerHandle> {
        let id = identity.unwrap_or_else(Identity::generate);
        let stream = TcpStream::connect(remote).await?;
        let (cmd_tx, handle) = Self::spawn(stream, PeerCtx {
            cfg, identity: id, remote, direction: Direction::Outbound
        }, events_tx);
        Ok(handle)
    }

    /// Accept an inbound connection and spawn the peer task.
    #[instrument(level = "info", skip(cfg))]
    pub async fn accept(
        stream: TcpStream,
        remote: SocketAddr,
        cfg: PeerConfig,
        identity: Option<Identity>,
        events_tx: mpsc::Sender<PeerEvent>,
    ) -> anyhow::Result<PeerHandle> {
        let id = identity.unwrap_or_else(Identity::generate);
        let (cmd_tx, handle) = Self::spawn(stream, PeerCtx {
            cfg, identity: id, remote, direction: Direction::Inbound
        }, events_tx);
        Ok(handle)
    }

    fn spawn(
        stream: TcpStream,
        ctx: PeerCtx,
        events_tx: mpsc::Sender<PeerEvent>,
    ) -> (mpsc::Sender<PeerCommand>, PeerHandle) {
        let (read_half, write_half) = stream.into_split();
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(ctx.cfg.max_frame_len);

        let mut reader = FramedRead::new(read_half, codec.clone());
        let mut writer = FramedWrite::new(write_half, codec);

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<PeerCommand>(1024);
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

        let remote = ctx.remote;
        let peer_id_hint = ctx.identity.id;

        let handle = PeerHandle {
            peer_id: Some(peer_id_hint),
            remote,
            cmd_tx: cmd_tx.clone(),
            shutdown_tx: shutdown_tx.clone(),
        };

        let cfg = ctx.cfg.clone();
        let identity = ctx.identity;
        #[allow(unused_mut)]
        let mut noise_opt: Option<NoiseState> = None;

        // Noise state wrapper (selected only if "noise" feature is enabled).
        #[cfg(feature = "noise")]
        type NoiseState = noise::NoiseChannel;
        #[cfg(not(feature = "noise"))]
        type NoiseState = ();

        let task: JoinHandle<()> = tokio::spawn(async move {
            info!(target: "p2p::peer", ?remote, "peer task started");

            // ------------------------------ Handshake ------------------------------
            let handshake_res = timeout(cfg.handshake_timeout, async {
                let hello = WireMessage::Hello {
                    version: PROTOCOL_V1,
                    peer_pk: identity.verifying.to_bytes(),
                };
                let hello_bytes = serde_json::to_vec(&hello).expect("serialize hello");

                // If Noise is enabled, perform minimal handshake payload exchange.
                #[cfg(feature = "noise")]
                let mut noise = match ctx.direction {
                    Direction::Outbound => noise::NoiseChannel::new_initiator(),
                    Direction::Inbound  => noise::NoiseChannel::new_responder(),
                }.and_then(|mut ch| {
                    // Send first handshake frame
                    ch.write_handshake_msg(&hello_bytes).map(|cipher| {
                        // send cipher as a length-delimited frame
                        Bytes::from(cipher)
                    }).map(|frame| (ch, frame))
                });

                #[cfg(feature = "noise")]
                {
                    match noise {
                        Ok((mut ch, frame)) => {
                            if let Err(e) = writer.send(frame.clone()).await {
                                error!(error=?e, "failed to send handshake frame");
                                return Err(anyhow::anyhow!(e));
                            }
                            // Read peer handshake response
                            let resp = reader.next().await
                                .ok_or_else(|| anyhow::anyhow!("eof during handshake"))??;
                            let plain = ch.read_handshake_msg(&resp)?;
                            let _peer_hello: WireMessage = serde_json::from_slice(&plain)?;
                            noise_opt = Some(ch);
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("noise init failed: {e}"));
                        }
                    }
                }

                #[cfg(not(feature = "noise"))]
                {
                    // Plaintext hello exchange (not authenticated/confidential).
                    if let Err(e) = writer.send(Bytes::from(hello_bytes.clone())).await {
                        error!(error=?e, "failed to send plaintext hello");
                        return Err(anyhow::anyhow!(e));
                    }
                    let resp = reader.next().await
                        .ok_or_else(|| anyhow::anyhow!("eof during handshake"))??;
                    let _peer_hello: WireMessage = serde_json::from_slice(&resp)?;
                }

                Ok::<_, anyhow::Error>(())
            }).await;

            if let Err(e) = handshake_res {
                error!(?e, "handshake timeout or failure");
                let _ = events_tx.send(PeerEvent::Closed(Some(anyhow::anyhow!("handshake failed")))).await;
                return;
            }

            info!(target="p2p::peer", ?remote, "handshake completed");
            let _ = events_tx.send(PeerEvent::HandshakeCompleted(identity.id, remote)).await;

            // ------------------------------- Loops --------------------------------
            let mut hb = interval(cfg.heartbeat_interval);
            let mut last_rx = Instant::now();

            loop {
                tokio::select! {
                    biased;

                    // External shutdown signal
                    _ = shutdown_rx.recv() => {
                        info!(target="p2p::peer", ?remote, "shutdown signal received");
                        break;
                    }

                    // Commands to send
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(PeerCommand::Close) | None => {
                                info!(target="p2p::peer", ?remote, "close requested");
                                break;
                            }
                            Some(PeerCommand::SendPing(seq)) => {
                                let frame = WireMessage::Ping { seq, at: now_millis() };
                                if let Err(e) = send_frame(&mut writer, &frame, cfg.write_frame_timeout, &mut noise_opt).await {
                                    error!(?e, "send ping failed");
                                    break;
                                }
                            }
                            Some(PeerCommand::SendApp(data)) => {
                                let frame = WireMessage::App { data: data.to_vec() };
                                if let Err(e) = send_frame(&mut writer, &frame, cfg.write_frame_timeout, &mut noise_opt).await {
                                    error!(?e, "send app failed");
                                    break;
                                }
                            }
                        }
                    }

                    // Heartbeat
                    _ = hb.tick() => {
                        let seq = now_millis();
                        let frame = WireMessage::Ping { seq, at: seq };
                        if let Err(e) = send_frame(&mut writer, &frame, cfg.write_frame_timeout, &mut noise_opt).await {
                            warn!(?e, "heartbeat ping failed");
                            break;
                        }
                    }

                    // Receiving frames with read timeout
                    received = timeout(cfg.read_frame_timeout, reader.next()) => {
                        match received {
                            Ok(Some(Ok(mut bytes))) => {
                                last_rx = Instant::now();

                                // If encrypted, decrypt first
                                #[cfg(feature="noise")]
                                if let Some(ch) = noise_opt.as_mut() {
                                    match ch.decrypt(&bytes) {
                                        Ok(plain) => { bytes = Bytes::from(plain); },
                                        Err(e) => { error!(?e, "decrypt failed"); break; }
                                    }
                                }

                                match serde_json::from_slice::<WireMessage>(&bytes) {
                                    Ok(WireMessage::Ping { seq, .. }) => {
                                        let pong = WireMessage::Pong { seq, at: now_millis() };
                                        if let Err(e) = send_frame(&mut writer, &pong, cfg.write_frame_timeout, &mut noise_opt).await {
                                            error!(?e, "send pong failed");
                                            break;
                                        }
                                    }
                                    Ok(WireMessage::Pong { seq, .. }) => {
                                        let _ = events_tx.send(PeerEvent::Pong(seq)).await;
                                    }
                                    Ok(WireMessage::App { data }) => {
                                        let _ = events_tx.send(PeerEvent::App(Bytes::from(data))).await;
                                    }
                                    Ok(WireMessage::Hello { .. }) => {
                                        // ignore late hello
                                        trace!("late hello ignored");
                                    }
                                    Err(e) => {
                                        warn!(?e, "invalid frame");
                                        break;
                                    }
                                }
                            }
                            Ok(Some(Err(e))) => {
                                warn!(?e, "read error");
                                break;
                            }
                            Ok(None) => {
                                info!("peer closed");
                                break;
                            }
                            Err(_) => {
                                // read timeout
                                if last_rx.elapsed() > cfg.idle_disconnect {
                                    warn!("idle disconnect");
                                    break;
                                }
                                // otherwise allow heartbeat to proceed
                                continue;
                            }
                        }
                    }
                }
            }

            let _ = events_tx.send(PeerEvent::Closed(None)).await;
            info!(target="p2p::peer", ?remote, "peer task stopped");
        });

        (cmd_tx, handle)
    }
}

// ------------------------------- Helpers -------------------------------------

#[inline]
fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[instrument(level="debug", skip(writer, msg, noise_opt))]
async fn send_frame(
    writer: &mut FramedWrite<tokio::net::tcp::OwnedWriteHalf, LengthDelimitedCodec>,
    msg: &WireMessage,
    write_to: Duration,
    #[allow(unused_mut)] noise_opt: &mut Option<NoiseState>,
) -> anyhow::Result<()> {
    let mut data = serde_json::to_vec(msg)?;
    #[cfg(feature="noise")]
    if let Some(ch) = noise_opt.as_mut() {
        data = ch.encrypt(&data)?;
    }
    timeout(write_to, writer.send(Bytes::from(data))).await??;
    Ok(())
}

// ------------------------------- Tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test(flavor="multi_thread", worker_threads = 2)]
    async fn peer_ping_pong_smoke() -> anyhow::Result<()> {
        tracing_subscriber::fmt().with_test_writer().init();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;

        let cfg = PeerConfig::default();
        let (events_tx, mut events_rx) = mpsc::channel::<PeerEvent>(64);

        // acceptor
        tokio::spawn({
            let cfg = cfg.clone();
            let events_tx = events_tx.clone();
            async move {
                let (stream, r) = listener.accept().await.unwrap();
                let _h = Peer::accept(stream, r, cfg, None, events_tx).await.unwrap();
            }
        });

        // dialer
        let handle = Peer::dial(local, cfg.clone(), None, events_tx.clone()).await?;

        // wait for handshake
        let mut got_handshake = false;
        let mut got_pong = false;

        // send ping
        handle.ping(42).await.unwrap();

        // read events
        let mut deadline = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(ev) = events_rx.recv().await {
                match ev {
                    PeerEvent::HandshakeCompleted(_, _) => { got_handshake = true; }
                    PeerEvent::Pong(42) => { got_pong = true; break; }
                    _ => {}
                }
            }
        }).await;

        assert!(deadline.is_ok(), "timed out waiting events");
        assert!(got_handshake, "handshake not observed");
        assert!(got_pong, "pong not received");

        handle.close().await.unwrap();
        Ok(())
    }
}
