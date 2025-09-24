//! IBC adapter for the Aethernova relayer.
//!
//! Responsibilities:
//! - Subscribe to IBC events (send_packet / write_acknowledgement / timeout_packet) via Tendermint WS.
//! - Query proofs for commitments/acks/receipts via IBC gRPC Query.
//! - Build ICS-04 messages (MsgRecvPacket / MsgAcknowledgement / MsgTimeout*).
//! - Broadcast signed tx bytes via cosmos.tx.v1beta1.Service/BroadcastTx.
//!
//! This module is feature-gated and backend-agnostic. Default backend targets Cosmos SDK chains.

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use thiserror::Error;
use tokio::{sync::broadcast, task::JoinHandle};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, error, info, warn};

use ibc::core::{
    channel::types::packet::Packet as IbcPacket,
    client::types::Height as IcsHeight,
    host::types::identifiers::{ChannelId, ClientId, ConnectionId, PortId, Sequence},
};
use ibc_proto::{
    ibc::{
        core::{
            channel::v1 as chan_v1,
            client::v1 as client_v1,
        },
    },
    protobuf::ProstAny,
};

#[cfg(feature = "cosmos-ws")]
use tendermint_rpc::{
    client::{Client, EventListener, SubscriptionClient, WebSocketClient, WebSocketClientDriver},
    query::Query,
    event::Event as TmEvent,
};

#[cfg(feature = "cosmos-grpc")]
use {
    tonic::{transport::Channel as GrpcChannel, Code, Status},
    cosmos_sdk_proto::cosmos::tx::v1beta1::{
        service_client::ServiceClient as TxServiceClient, BroadcastTxRequest, BroadcastMode,
    },
    ibc_proto::ibc::core::channel::v1::query_client::QueryClient as IbcQueryClient,
    ibc_proto::ibc::core::channel::v1::{
        QueryPacketCommitmentRequest, QueryPacketAcknowledgementRequest, QueryPacketReceiptRequest,
    },
};

/// Chain configuration used by the adapter.
#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub chain_id: String,
    /// Tendermint RPC websocket endpoint, e.g. "ws://host:26657/websocket"
    pub tm_ws_endpoint: String,
    /// Cosmos SDK gRPC endpoint, e.g. "http://host:9090"
    pub grpc_endpoint: String,
    /// Bech32 prefix for account addresses (informational; signing happens upstream).
    pub bech32_prefix: String,
    /// Default signer address (string) used for message `signer` field.
    pub default_signer: String,
    /// Optional per-chain broadcast mode override.
    pub broadcast_mode: Option<BroadcastMode>,
    /// Timeouts
    pub request_timeout: Duration,
    pub ws_reconnect_backoff: Duration,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            chain_id: "unknown-1".to_string(),
            tm_ws_endpoint: "ws://127.0.0.1:26657/websocket".to_string(),
            grpc_endpoint: "http://127.0.0.1:9090".to_string(),
            bech32_prefix: "cosmos".to_string(),
            default_signer: String::new(),
            broadcast_mode: Some(BroadcastMode::Sync),
            request_timeout: Duration::from_secs(10),
            ws_reconnect_backoff: Duration::from_secs(3),
        }
    }
}

/// High-level IBC events of interest for relaying.
#[derive(Clone, Debug)]
pub enum IbcEvent {
    /// Emitted when chain A logs an outgoing packet that should be relayed to chain B.
    SendPacket {
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        packet: IbcPacket,
    },
    /// Emitted when chain B writes acknowledgement which should be relayed back to chain A.
    WriteAcknowledgement {
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        acknowledgement: Bytes,
        packet: IbcPacket,
    },
    /// Emitted when a packet timed out and should be relayed back to close the loop.
    TimeoutPacket {
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        packet: IbcPacket,
    },
}

impl fmt::Display for IbcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IbcEvent::SendPacket { port_id, channel_id, sequence, .. } => {
                write!(f, "SendPacket {}.{} seq={}", port_id, channel_id, sequence)
            }
            IbcEvent::WriteAcknowledgement { port_id, channel_id, sequence, .. } => {
                write!(f, "WriteAck {}.{} seq={}", port_id, channel_id, sequence)
            }
            IbcEvent::TimeoutPacket { port_id, channel_id, sequence, .. } => {
                write!(f, "Timeout {}.{} seq={}", port_id, channel_id, sequence)
            }
        }
    }
}

/// Errors surfaced by the adapter.
#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("grpc error: {0}")]
    Grpc(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AdapterError>;

/// Abstract IBC adapter trait. Concrete impl may target Cosmos SDK chains.
#[async_trait]
pub trait IbcAdapter: Send + Sync {
    /// Start streaming IBC events. Returns a broadcast receiver stream and a join handle of the WS driver.
    async fn stream_events(&self) -> Result<(BroadcastStream<IbcEvent>, JoinHandle<()>)>;

    /// Query proof for a packet commitment on this chain (source chain).
    async fn query_packet_commitment_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle>;

    /// Query proof for a packet acknowledgement on this chain (destination chain).
    async fn query_packet_ack_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle>;

    /// Query proof for a packet receipt (for unordered channels, used in timeouts).
    async fn query_packet_receipt_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle>;

    /// Build MsgRecvPacket given a packet and proof from the counterparty.
    fn build_msg_recv_packet(
        &self,
        packet: IbcPacket,
        proof: ProofBundle,
        signer: Option<&str>,
    ) -> chan_v1::MsgRecvPacket;

    /// Build MsgAcknowledgement given the acknowledgement bytes and proof height.
    fn build_msg_acknowledgement(
        &self,
        packet: IbcPacket,
        acknowledgement: Bytes,
        proof: ProofBundle,
        signer: Option<&str>,
    ) -> chan_v1::MsgAcknowledgement;

    /// Build MsgTimeout (or TimeoutOnClose) message with necessary proofs.
    fn build_msg_timeout(
        &self,
        packet: IbcPacket,
        proof: ProofBundle,
        next_sequence_recv: Option<u64>,
        signer: Option<&str>,
    ) -> chan_v1::MsgTimeout;

    /// Broadcast a signed transaction (tx bytes are signed/assembled upstream).
    async fn broadcast_signed_tx(&self, tx_bytes: Bytes, mode: Option<BroadcastMode>) -> Result<()>;
}

/// Proof bundle with height for ICS-04 messages.
#[derive(Clone, Debug)]
pub struct ProofBundle {
    pub proof: Bytes,
    pub proof_height: client_v1::Height,
}

impl ProofBundle {
    pub fn new(proof: Vec<u8>, proof_height: client_v1::Height) -> Self {
        Self { proof: Bytes::from(proof), proof_height }
    }
}

/// Cosmos SDK implementation of the adapter.
pub struct CosmosIbcAdapter {
    cfg: Arc<ChainConfig>,
    /// Event bus for rebroadcasting parsed IBC events.
    tx_evt: broadcast::Sender<IbcEvent>,
}

impl CosmosIbcAdapter {
    pub fn new(cfg: ChainConfig) -> Self {
        let (tx_evt, _rx) = broadcast::channel(1024);
        Self { cfg: Arc::new(cfg), tx_evt }
    }

    fn default_signer(&self, signer: Option<&str>) -> String {
        signer
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.cfg.default_signer.clone())
    }

    #[cfg(feature = "cosmos-grpc")]
    async fn grpc(&self) -> std::result::Result<GrpcChannel, AdapterError> {
        GrpcChannel::from_shared(self.cfg.grpc_endpoint.clone())
            .map_err(|e| AdapterError::Transport(e.to_string()))?
            .connect_timeout(self.cfg.request_timeout)
            .connect()
            .await
            .map_err(|e| AdapterError::Transport(e.to_string()))
    }

    #[cfg(feature = "cosmos-ws")]
    async fn start_ws_driver(&self) -> Result<(WebSocketClient, JoinHandle<()>)> {
        let (ws_client, driver) = WebSocketClient::new(self.cfg.tm_ws_endpoint.as_str())
            .await
            .map_err(|e| AdapterError::Transport(e.to_string()))?;

        let handle = tokio::spawn(async move {
            if let Err(e) = driver.run().await {
                error!("tendermint ws driver stopped: {e}");
            }
        });

        Ok((ws_client, handle))
    }

    #[cfg(feature = "cosmos-ws")]
    fn parse_tm_event(&self, ev: &TmEvent) -> Option<IbcEvent> {
        // Tendermint events expose composite event types with attributes.
        // IBC-Go emits event types "send_packet", "write_acknowledgement", "timeout_packet".
        // We map minimal fields needed for relaying.
        let ty = ev.kind.to_string(); // e.g., "send_packet"
        let attrs = ev.attributes();
        let mut get = |k: &str| -> Option<String> {
            attrs.get(k).and_then(|v| v.iter().next()).cloned()
        };

        match ty.as_str() {
            "send_packet" => {
                let port_id = get("packet_src_port")?;
                let channel_id = get("packet_src_channel")?;
                let seq = get("packet_sequence")?.parse::<u64>().ok()?;
                // raw packet data fields
                let dst_port = get("packet_dst_port")?;
                let dst_channel = get("packet_dst_channel")?;
                let data_b64 = get("packet_data")?;
                let timeout_height = get("packet_timeout_height")?;
                let timeout_ts = get("packet_timeout_timestamp")?;

                let packet = IbcPacket {
                    seq_on_a: Sequence::from(seq),
                    src_port_id_on_a: PortId::from_str(&port_id).ok()?,
                    src_channel_id_on_a: ChannelId::from_str(&channel_id).ok()?,
                    dst_port_id_on_b: PortId::from_str(&dst_port).ok()?,
                    dst_channel_id_on_b: ChannelId::from_str(&dst_channel).ok()?,
                    data: base64::decode(data_b64).ok()?.into(),
                    timeout_height_on_b: parse_height_str(timeout_height.as_str()).unwrap_or_default(),
                    timeout_timestamp_on_b: timeout_ts.parse::<u64>().unwrap_or_default().into(),
                };

                Some(IbcEvent::SendPacket {
                    port_id: PortId::from_str(&port_id).ok()?,
                    channel_id: ChannelId::from_str(&channel_id).ok()?,
                    sequence: Sequence::from(seq),
                    packet,
                })
            }
            "write_acknowledgement" => {
                let port_id = get("packet_dst_port")?;
                let channel_id = get("packet_dst_channel")?;
                let seq = get("packet_sequence")?.parse::<u64>().ok()?;
                let ack_b64 = get("packet_ack")?;
                // Optional: reconstruct packet fields as above if attributes present.
                // If missing, we skip embedding packet (relayer may re-query).
                let ack = base64::decode(ack_b64).ok()?.into();
                // For robustness, we leave packet empty if attrs are incomplete.
                None::<IbcEvent>.or_else(|| {
                    let src_port = get("packet_src_port")?;
                    let src_channel = get("packet_src_channel")?;
                    let data_b64 = get("packet_data")?;
                    let timeout_height = get("packet_timeout_height")?;
                    let timeout_ts = get("packet_timeout_timestamp")?;
                    let packet = IbcPacket {
                        seq_on_a: Sequence::from(seq),
                        src_port_id_on_a: PortId::from_str(&src_port).ok()?,
                        src_channel_id_on_a: ChannelId::from_str(&src_channel).ok()?,
                        dst_port_id_on_b: PortId::from_str(&port_id).ok()?,
                        dst_channel_id_on_b: ChannelId::from_str(&channel_id).ok()?,
                        data: base64::decode(data_b64).ok()?.into(),
                        timeout_height_on_b: parse_height_str(timeout_height.as_str()).unwrap_or_default(),
                        timeout_timestamp_on_b: timeout_ts.parse::<u64>().unwrap_or_default().into(),
                    };
                    Some(IbcEvent::WriteAcknowledgement {
                        port_id: PortId::from_str(&port_id).ok()?,
                        channel_id: ChannelId::from_str(&channel_id).ok()?,
                        sequence: Sequence::from(seq),
                        acknowledgement: ack,
                        packet,
                    })
                })
            }
            "timeout_packet" => {
                let port_id = get("packet_src_port")?;
                let channel_id = get("packet_src_channel")?;
                let seq = get("packet_sequence")?.parse::<u64>().ok()?;
                // If packet fields exist, reconstruct; else create a minimal packet shell.
                let ev = if let (Some(dst_port), Some(dst_chan), Some(data_b64), Some(th), Some(tts)) = (
                    get("packet_dst_port"),
                    get("packet_dst_channel"),
                    get("packet_data"),
                    get("packet_timeout_height"),
                    get("packet_timeout_timestamp"),
                ) {
                    let packet = IbcPacket {
                        seq_on_a: Sequence::from(seq),
                        src_port_id_on_a: PortId::from_str(&port_id).ok()?,
                        src_channel_id_on_a: ChannelId::from_str(&channel_id).ok()?,
                        dst_port_id_on_b: PortId::from_str(&dst_port).ok()?,
                        dst_channel_id_on_b: ChannelId::from_str(&dst_chan).ok()?,
                        data: base64::decode(data_b64).ok()?.into(),
                        timeout_height_on_b: parse_height_str(th.as_str()).unwrap_or_default(),
                        timeout_timestamp_on_b: tts.parse::<u64>().unwrap_or_default().into(),
                    };
                    Some(IbcEvent::TimeoutPacket {
                        port_id: PortId::from_str(&port_id).ok()?,
                        channel_id: ChannelId::from_str(&channel_id).ok()?,
                        sequence: Sequence::from(seq),
                        packet,
                    })
                } else {
                    None
                };
                ev
            }
            _ => None,
        }
    }
}

#[async_trait]
impl IbcAdapter for CosmosIbcAdapter {
    #[allow(unused_mut)]
    async fn stream_events(&self) -> Result<(BroadcastStream<IbcEvent>, JoinHandle<()>)> {
        #[cfg(not(feature = "cosmos-ws"))]
        {
            return Err(AdapterError::Unsupported(
                "build without `cosmos-ws` feature: event streaming unavailable".into(),
            ));
        }

        #[cfg(feature = "cosmos-ws")]
        {
            let (client, driver) = self.start_ws_driver().await?;

            // We subscribe to three event types. Some nodes may restrict OR queries; do multiple subs.
            let mut subs: Vec<_> = Vec::new();
            for q in &[
                Query::from("tm.event='Tx' AND send_packet.packet_sequence EXISTS"),
                Query::from("tm.event='Tx' AND write_acknowledgement.packet_sequence EXISTS"),
                Query::from("tm.event='Tx' AND timeout_packet.packet_sequence EXISTS"),
            ] {
                match client.subscribe(q.clone()).await {
                    Ok(s) => subs.push(s),
                    Err(e) => warn!("subscription failed for {q:?}: {e}"),
                }
            }

            let tx_evt = self.tx_evt.clone();
            let join = tokio::spawn(async move {
                let mut streams = futures::stream::select_all(subs.into_iter().map(|s| s.into_stream()));
                while let Some(Ok(ev)) = streams.next().await {
                    if let Some(parsed) = Self { cfg: Arc::new(ChainConfig::default()), tx_evt: tx_evt.clone() }.parse_tm_event(&ev) {
                        let _ = tx_evt.send(parsed);
                    }
                }
            });

            Ok((BroadcastStream::new(self.tx_evt.subscribe()), tokio::spawn(async move {
                let _ = join.await;
                let _ = driver.await;
            })))
        }
    }

    #[cfg(feature = "cosmos-grpc")]
    async fn query_packet_commitment_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle> {
        let chan = self.grpc().await?;
        let mut q = IbcQueryClient::new(chan);
        let req = QueryPacketCommitmentRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            sequence: sequence.into(),
        };
        let resp = q.packet_commitment(req).await.map_err(|e| AdapterError::Grpc(e.to_string()))?.into_inner();
        if resp.proof.is_empty() {
            return Err(AdapterError::NotFound("empty packet commitment proof".into()));
        }
        Ok(ProofBundle::new(resp.proof, resp.proof_height.unwrap_or_default()))
    }

    #[cfg(not(feature = "cosmos-grpc"))]
    async fn query_packet_commitment_proof(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _sequence: Sequence,
    ) -> Result<ProofBundle> {
        Err(AdapterError::Unsupported("build without `cosmos-grpc` feature".into()))
    }

    #[cfg(feature = "cosmos-grpc")]
    async fn query_packet_ack_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle> {
        let chan = self.grpc().await?;
        let mut q = IbcQueryClient::new(chan);
        let req = QueryPacketAcknowledgementRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            sequence: sequence.into(),
        };
        let resp = q.packet_acknowledgement(req).await.map_err(|e| AdapterError::Grpc(e.to_string()))?.into_inner();
        if resp.proof.is_empty() {
            return Err(AdapterError::NotFound("empty packet ack proof".into()));
        }
        Ok(ProofBundle::new(resp.proof, resp.proof_height.unwrap_or_default()))
    }

    #[cfg(not(feature = "cosmos-grpc"))]
    async fn query_packet_ack_proof(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _sequence: Sequence,
    ) -> Result<ProofBundle> {
        Err(AdapterError::Unsupported("build without `cosmos-grpc` feature".into()))
    }

    #[cfg(feature = "cosmos-grpc")]
    async fn query_packet_receipt_proof(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<ProofBundle> {
        let chan = self.grpc().await?;
        let mut q = IbcQueryClient::new(chan);
        let req = QueryPacketReceiptRequest {
            port_id: port_id.to_string(),
            channel_id: channel_id.to_string(),
            sequence: sequence.into(),
        };
        let resp = q.packet_receipt(req).await.map_err(|e| AdapterError::Grpc(e.to_string()))?.into_inner();
        if resp.proof.is_empty() {
            return Err(AdapterError::NotFound("empty packet receipt proof".into()));
        }
        Ok(ProofBundle::new(resp.proof, resp.proof_height.unwrap_or_default()))
    }

    #[cfg(not(feature = "cosmos-grpc"))]
    async fn query_packet_receipt_proof(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
        _sequence: Sequence,
    ) -> Result<ProofBundle> {
        Err(AdapterError::Unsupported("build without `cosmos-grpc` feature".into()))
    }

    fn build_msg_recv_packet(
        &self,
        packet: IbcPacket,
        proof: ProofBundle,
        signer: Option<&str>,
    ) -> chan_v1::MsgRecvPacket {
        chan_v1::MsgRecvPacket {
            packet: Some(to_proto_packet(packet)),
            proof_commitment: proof.proof.to_vec(),
            proof_height: Some(proof.proof_height),
            signer: self.default_signer(signer),
        }
    }

    fn build_msg_acknowledgement(
        &self,
        packet: IbcPacket,
        acknowledgement: Bytes,
        proof: ProofBundle,
        signer: Option<&str>,
    ) -> chan_v1::MsgAcknowledgement {
        chan_v1::MsgAcknowledgement {
            packet: Some(to_proto_packet(packet)),
            acknowledgement: acknowledgement.to_vec(),
            proof_acked: proof.proof.to_vec(),
            proof_height: Some(proof.proof_height),
            signer: self.default_signer(signer),
        }
    }

    fn build_msg_timeout(
        &self,
        packet: IbcPacket,
        proof: ProofBundle,
        next_sequence_recv: Option<u64>,
        signer: Option<&str>,
    ) -> chan_v1::MsgTimeout {
        chan_v1::MsgTimeout {
            packet: Some(to_proto_packet(packet)),
            proof_unreceived: proof.proof.to_vec(),
            proof_height: Some(proof.proof_height),
            next_sequence_recv: next_sequence_recv.unwrap_or_default(),
            signer: self.default_signer(signer),
        }
    }

    #[cfg(feature = "cosmos-grpc")]
    async fn broadcast_signed_tx(&self, tx_bytes: Bytes, mode: Option<BroadcastMode>) -> Result<()> {
        let chan = self.grpc().await?;
        let mut txc = TxServiceClient::new(chan);
        let req = BroadcastTxRequest {
            tx_bytes: tx_bytes.to_vec(),
            mode: mode.or(self.cfg.broadcast_mode).unwrap_or(BroadcastMode::Sync).into(),
        };
        let resp = txc.broadcast_tx(req).await.map_err(|e| AdapterError::Grpc(e.to_string()))?.into_inner();
        if let Some(tx_resp) = resp.tx_response {
            if tx_resp.code != 0 {
                return Err(AdapterError::Internal(format!(
                    "broadcast failed: code={} raw_log={}",
                    tx_resp.code, tx_resp.raw_log
                )));
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "cosmos-grpc"))]
    async fn broadcast_signed_tx(&self, _tx_bytes: Bytes, _mode: Option<BroadcastMode>) -> Result<()> {
        Err(AdapterError::Unsupported("build without `cosmos-grpc` feature".into()))
    }
}

/// Convert ibc::Packet to ibc-proto Packet.
fn to_proto_packet(p: IbcPacket) -> chan_v1::Packet {
    chan_v1::Packet {
        sequence: u64::from(p.seq_on_a),
        source_port: p.src_port_id_on_a.to_string(),
        source_channel: p.src_channel_id_on_a.to_string(),
        destination_port: p.dst_port_id_on_b.to_string(),
        destination_channel: p.dst_channel_id_on_b.to_string(),
        data: p.data.to_vec(),
        timeout_height: Some(client_v1::Height {
            revision_number: p.timeout_height_on_b.revision_number(),
            revision_height: p.timeout_height_on_b.revision_height(),
        }),
        timeout_timestamp: p.timeout_timestamp_on_b.as_u64(),
    }
}

/// Parse a "revision-number/revision-height" string into IcsHeight; accept "0-0" or "0/0".
fn parse_height_str(s: &str) -> Option<IcsHeight> {
    if s.is_empty() { return None; }
    let norm = s.replace('/', "-");
    let mut parts = norm.split('-');
    let rn = parts.next()?.parse::<u64>().ok()?;
    let rh = parts.next()?.parse::<u64>().ok()?;
    Some(IcsHeight::new(rn, rh))
}
