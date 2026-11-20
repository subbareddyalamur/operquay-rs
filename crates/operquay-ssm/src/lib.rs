#![forbid(unsafe_code)]

//! Clean-room AWS SSM `AgentMessage` binary framing & in-memory `SsmVirtualStream`
//! (`AsyncRead + AsyncWrite`) eliminating spawned `aws`, `session-manager-plugin`,
//! `socat`, and loopback `33890..33999` sockets (`ADR-0004`).

use std::future::Future;
use std::io;

pub mod live;
pub use live::{
    build_open_data_channel_json, connect_ssm_datachannel_stream, encode_ssm_resize,
    open_ssm_shell_channel, SsmShellChannel,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use uuid::Uuid;

pub const AGENT_MSG_HEADER_LEN: usize = 116;

pub mod message_type {
    pub const INPUT_STREAM_DATA: &str = "input_stream_data";
    pub const OUTPUT_STREAM_DATA: &str = "output_stream_data";
    pub const ACKNOWLEDGE: &str = "acknowledge";
    pub const CHANNEL_CLOSED: &str = "channel_closed";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PayloadType {
    Output = 1,
    Error = 2,
    Size = 3,
    Parameter = 4,
    HandshakeRequest = 5,
    HandshakeResponse = 6,
    HandshakeComplete = 7,
    Flag = 10,
}

impl PayloadType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Output),
            2 => Some(Self::Error),
            3 => Some(Self::Size),
            4 => Some(Self::Parameter),
            5 => Some(Self::HandshakeRequest),
            6 => Some(Self::HandshakeResponse),
            7 => Some(Self::HandshakeComplete),
            10 => Some(Self::Flag),
            _ => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SsmCodecError {
    #[error("SSM AgentMessage truncated ({0} bytes)")]
    Truncated(usize),
    #[error("unsupported header length {0}")]
    UnsupportedHeaderLen(u32),
    #[error("payload SHA-256 digest mismatch")]
    DigestMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMessage {
    pub message_type: String,
    pub schema_version: u32,
    pub created_date_ms: u64,
    pub sequence_number: i64,
    pub flags: u64,
    pub message_id: Uuid,
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

impl AgentMessage {
    #[must_use]
    pub fn data(
        message_type: &str,
        sequence_number: i64,
        payload_type: PayloadType,
        payload: Vec<u8>,
    ) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        Self {
            message_type: message_type.to_owned(),
            schema_version: 1,
            created_date_ms: now_ms,
            sequence_number,
            flags: 0,
            message_id: Uuid::new_v4(),
            payload_type: payload_type as u32,
            payload,
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(&self.payload).into();
        let mut out = BytesMut::with_capacity(4 + AGENT_MSG_HEADER_LEN + self.payload.len());
        out.put_u32(AGENT_MSG_HEADER_LEN as u32);

        let mut mt_padded = [b' '; 32];
        let mt_bytes = self.message_type.as_bytes();
        let copy_n = mt_bytes.len().min(32);
        mt_padded[..copy_n].copy_from_slice(&mt_bytes[..copy_n]);
        out.put_slice(&mt_padded);

        out.put_u32(self.schema_version);
        out.put_u64(self.created_date_ms);
        out.put_i64(self.sequence_number);
        out.put_u64(self.flags);
        // AWS SSM AgentMessage wire order stores UUID LSB[8..16] at offset 64 and MSB[0..8] at offset 72.
        let uuid_bytes = self.message_id.as_bytes();
        out.put_slice(&uuid_bytes[8..16]);
        out.put_slice(&uuid_bytes[..8]);
        out.put_slice(&digest);
        out.put_u32(self.payload_type);
        out.put_u32(self.payload.len() as u32);
        out.put_slice(&self.payload);
        out.to_vec()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, SsmCodecError> {
        if raw.len() < 4 + AGENT_MSG_HEADER_LEN {
            return Err(SsmCodecError::Truncated(raw.len()));
        }
        let header_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if usize::try_from(header_len).ok() != Some(AGENT_MSG_HEADER_LEN) {
            return Err(SsmCodecError::UnsupportedHeaderLen(header_len));
        }

        let mt_raw = &raw[4..36];
        let message_type = String::from_utf8_lossy(mt_raw)
            .trim_end_matches([' ', '\0'])
            .to_owned();
        let schema_version = u32::from_be_bytes([raw[36], raw[37], raw[38], raw[39]]);
        let created_date_ms = u64::from_be_bytes(raw[40..48].try_into().unwrap_or([0; 8]));
        let sequence_number = i64::from_be_bytes(raw[48..56].try_into().unwrap_or([0; 8]));
        let flags = u64::from_be_bytes(raw[56..64].try_into().unwrap_or([0; 8]));
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes[8..16].copy_from_slice(&raw[64..72]);
        uuid_bytes[..8].copy_from_slice(&raw[72..80]);
        let message_id = Uuid::from_bytes(uuid_bytes);
        let expected_digest = &raw[80..112];
        let payload_type = u32::from_be_bytes([raw[112], raw[113], raw[114], raw[115]]);
        let payload_len = u32::from_be_bytes([raw[116], raw[117], raw[118], raw[119]]) as usize;

        if raw.len() < 120 + payload_len {
            return Err(SsmCodecError::Truncated(raw.len()));
        }
        let payload = raw[120..120 + payload_len].to_vec();
        let actual_digest: [u8; 32] = Sha256::digest(&payload).into();
        if actual_digest.as_slice() != expected_digest {
            return Err(SsmCodecError::DigestMismatch);
        }

        Ok(Self {
            message_type,
            schema_version,
            created_date_ms,
            sequence_number,
            flags,
            message_id,
            payload_type,
            payload,
        })
    }
}

type PermitFuture = Pin<Box<dyn Future<Output = Option<mpsc::OwnedPermit<Vec<u8>>>> + Send>>;

/// In-process virtual TCP-equivalent stream multiplexing RDP, VNC, or SSH bytes over AWS SSM
/// `AgentMessage` channels (`AsyncRead + AsyncWrite`), eliminating `session-manager-plugin` & `socat`.
pub struct SsmVirtualStream {
    rx_frames: mpsc::Receiver<Vec<u8>>,
    tx_frames: mpsc::Sender<Vec<u8>>,
    seq_out: Arc<AtomicI64>,
    read_pending: BytesMut,
    pending_permit: Option<PermitFuture>,
}

impl SsmVirtualStream {
    #[must_use]
    pub fn new(rx_frames: mpsc::Receiver<Vec<u8>>, tx_frames: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            rx_frames,
            tx_frames,
            seq_out: Arc::new(AtomicI64::new(0)),
            read_pending: BytesMut::with_capacity(64 * 1024),
            pending_permit: None,
        }
    }

    fn build_outbound_frame(seq_out: &AtomicI64, buf: &[u8]) -> Vec<u8> {
        let seq = seq_out.fetch_add(1, Ordering::Relaxed);
        AgentMessage::data(
            message_type::INPUT_STREAM_DATA,
            seq,
            PayloadType::Output,
            buf.to_vec(),
        )
        .encode()
    }

    /// Create a connected local pair of `SsmVirtualStream`s passing real SHA-256-verified
    /// `AgentMessage` binary frames between endpoints in memory (for loopback tunneling & tests).
    #[must_use]
    pub fn loopback_pair(bound: usize) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel(bound);
        let (b_tx, a_rx) = mpsc::channel(bound);
        (Self::new(a_rx, a_tx), Self::new(b_rx, b_tx))
    }
}

impl AsyncRead for SsmVirtualStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_pending.is_empty() {
            let take = buf.remaining().min(self.read_pending.len());
            let chunk = self.read_pending.split_to(take);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.rx_frames.poll_recv(cx) {
                Poll::Ready(Some(raw)) => {
                    let msg = AgentMessage::decode(&raw)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if msg.message_type == message_type::CHANNEL_CLOSED {
                        return Poll::Ready(Ok(()));
                    }
                    if msg.message_type == message_type::ACKNOWLEDGE || msg.payload.is_empty() {
                        continue;
                    }
                    let take = buf.remaining().min(msg.payload.len());
                    buf.put_slice(&msg.payload[..take]);
                    if take < msg.payload.len() {
                        self.read_pending.extend_from_slice(&msg.payload[take..]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SsmVirtualStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Some(fut) = self.pending_permit.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Some(permit)) => {
                        self.pending_permit = None;
                        let frame = Self::build_outbound_frame(&self.seq_out, buf);
                        permit.send(frame);
                        return Poll::Ready(Ok(buf.len()));
                    }
                    Poll::Ready(None) => {
                        self.pending_permit = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "SSM outbound channel closed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            match self.tx_frames.clone().try_reserve_owned() {
                Ok(permit) => {
                    let frame = Self::build_outbound_frame(&self.seq_out, buf);
                    permit.send(frame);
                    return Poll::Ready(Ok(buf.len()));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let sender = self.tx_frames.clone();
                    self.pending_permit =
                        Some(Box::pin(async move { sender.reserve_owned().await.ok() }));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "SSM outbound channel closed",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let seq = self.seq_out.fetch_add(1, Ordering::Relaxed);
        let close = AgentMessage::data(
            message_type::CHANNEL_CLOSED,
            seq,
            PayloadType::Flag,
            Vec::new(),
        );
        let _ = self.tx_frames.try_send(close.encode());
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn encodes_and_verifies_agent_message_sha256_integrity() {
        let msg = AgentMessage::data(
            message_type::INPUT_STREAM_DATA,
            42,
            PayloadType::Output,
            b"RDP-TPKT-PAYLOAD".to_vec(),
        );
        let mut wire = msg.encode();
        let decoded = AgentMessage::decode(&wire).unwrap();
        assert_eq!(decoded.sequence_number, 42);
        assert_eq!(decoded.message_id, msg.message_id);
        assert_eq!(decoded.payload, b"RDP-TPKT-PAYLOAD");
        assert_eq!(&wire[64..72], &msg.message_id.as_bytes()[8..16]);
        assert_eq!(&wire[72..80], &msg.message_id.as_bytes()[..8]);

        // Flip 1 bit in payload -> digest check rejects cleanly
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        assert_eq!(
            AgentMessage::decode(&wire),
            Err(SsmCodecError::DigestMismatch)
        );
    }

    #[tokio::test]
    async fn streams_bytes_end_to_end_over_in_process_ssm_virtual_stream() {
        let (mut left, mut right) = SsmVirtualStream::loopback_pair(16);
        left.write_all(b"HELLO_OVER_SSM").await.unwrap();
        let mut buf = [0u8; 14];
        right.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO_OVER_SSM");
    }
}
