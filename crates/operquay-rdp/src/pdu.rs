use bytes::{BufMut, BytesMut};
use operquay_core::settings::RdpSecurityMode;
use thiserror::Error;

pub const TPKT_VERSION: u8 = 0x03;

/// Security protocol bitmask flags per `[MS-RDPBCGR] §2.2.1.1.1`.
pub mod protocol_flags {
    pub const RDP: u32 = 0x0000_0000;
    pub const SSL: u32 = 0x0000_0001;
    pub const HYBRID: u32 = 0x0000_0002;
    pub const RDSTLS: u32 = 0x0000_0004;
    pub const HYBRID_EX: u32 = 0x0000_0008;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationProtocol {
    ClassicRdp,
    TlsOnly,
    HybridNla,
    HybridExNla,
    Any,
}

impl From<RdpSecurityMode> for NegotiationProtocol {
    fn from(mode: RdpSecurityMode) -> Self {
        match mode {
            RdpSecurityMode::Any | RdpSecurityMode::Vmconnect => Self::Any,
            RdpSecurityMode::Nla => Self::HybridNla,
            RdpSecurityMode::NlaExt => Self::HybridExNla,
            RdpSecurityMode::Tls => Self::TlsOnly,
            RdpSecurityMode::ClassicRdp => Self::ClassicRdp,
        }
    }
}

impl NegotiationProtocol {
    #[must_use]
    pub const fn requested_protocols_mask(self) -> u32 {
        match self {
            Self::ClassicRdp => protocol_flags::RDP,
            Self::TlsOnly => protocol_flags::SSL,
            Self::HybridNla => protocol_flags::SSL | protocol_flags::HYBRID,
            Self::HybridExNla | Self::Any => {
                protocol_flags::SSL | protocol_flags::HYBRID | protocol_flags::HYBRID_EX
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RdpPduError {
    #[error("packet truncated (needed {needed}, got {got})")]
    Truncated { needed: usize, got: usize },
    #[error("invalid TPKT version 0x{0:02x}")]
    InvalidTpktVersion(u8),
    #[error("X.224 negotiation failure code 0x{0:08x}")]
    NegotiationFailed(u32),
    #[error("malformed Fast-Path header")]
    InvalidFastPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X224Request {
    pub cookie: String,
    pub requested_protocols: u32,
}

impl X224Request {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut x224 = BytesMut::with_capacity(64);
        // Reserve length byte filled after body construction.
        x224.put_u8(0);
        x224.put_u8(0xE0); // CR-TPDU
        x224.put_u16(0x0000); // DST-REF
        x224.put_u16(0x0000); // SRC-REF
        x224.put_u8(0x00); // CLASS 0

        if !self.cookie.is_empty() {
            x224.put_slice(b"Cookie: mstshash=");
            x224.put_slice(self.cookie.as_bytes());
            x224.put_slice(b"\r\n");
        }

        // RDP_NEG_REQ: type=0x01, flags=0x00, len=8, requestedProtocols
        x224.put_u8(0x01);
        x224.put_u8(0x00);
        x224.put_u16_le(8);
        x224.put_u32_le(self.requested_protocols);

        x224[0] = (x224.len() - 1) as u8;

        let total_len = 4 + x224.len();
        let mut tpkt = BytesMut::with_capacity(total_len);
        tpkt.put_u8(TPKT_VERSION);
        tpkt.put_u8(0x00);
        tpkt.put_u16(total_len as u16);
        tpkt.extend_from_slice(&x224);
        tpkt.to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X224Confirm {
    pub selected_protocol: u32,
    pub flags: u8,
}

impl X224Confirm {
    pub fn parse(packet: &[u8]) -> Result<Self, RdpPduError> {
        if packet.len() < 11 {
            return Err(RdpPduError::Truncated {
                needed: 11,
                got: packet.len(),
            });
        }
        if packet[0] != TPKT_VERSION {
            return Err(RdpPduError::InvalidTpktVersion(packet[0]));
        }
        let tpkt_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if packet.len() < tpkt_len || tpkt_len < 11 {
            return Err(RdpPduError::Truncated {
                needed: tpkt_len,
                got: packet.len(),
            });
        }
        if tpkt_len == 11 {
            // Classic RDP CC-TPDU without RDP_NEG_RSP extension.
            return Ok(Self {
                selected_protocol: protocol_flags::RDP,
                flags: 0,
            });
        }
        if packet.len() < 19 {
            return Err(RdpPduError::Truncated {
                needed: 19,
                got: packet.len(),
            });
        }
        let neg_type = packet[11];
        let neg_flags = packet[12];
        let val = u32::from_le_bytes([packet[15], packet[16], packet[17], packet[18]]);
        if neg_type == 0x03 {
            return Err(RdpPduError::NegotiationFailed(val));
        }
        Ok(Self {
            selected_protocol: val,
            flags: neg_flags,
        })
    }
}

/// `[MS-RDPBCGR]` Fast-Path input events sent prior to frame flushes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastPathInputEvent {
    Scancode {
        extended: bool,
        release: bool,
        code: u8,
    },
    Unicode {
        release: bool,
        code_unit: u16,
    },
    Mouse {
        flags: u16,
        x: u16,
        y: u16,
    },
    SyncLocks {
        scroll: bool,
        num: bool,
        caps: bool,
        kana: bool,
    },
}

impl FastPathInputEvent {
    #[must_use]
    pub fn encode_single(&self) -> Vec<u8> {
        let mut body = BytesMut::with_capacity(12);
        match *self {
            Self::Scancode {
                extended,
                release,
                code,
            } => {
                let mut event_flags = 0u8;
                if release {
                    event_flags |= 0x01;
                }
                if extended {
                    event_flags |= 0x02;
                }
                // eventCode = 0 (SCANCODE) shifted << 5 | eventFlags
                body.put_u8(event_flags);
                body.put_u8(code);
            }
            Self::Unicode { release, code_unit } => {
                let flags = u8::from(release);
                body.put_u8((0x04 << 5) | flags);
                body.put_u16_le(code_unit);
            }
            Self::Mouse { flags, x, y } => {
                body.put_u8(0x01 << 5);
                body.put_u16_le(flags);
                body.put_u16_le(x);
                body.put_u16_le(y);
            }
            Self::SyncLocks {
                scroll,
                num,
                caps,
                kana,
            } => {
                let mut mask = 0u8;
                if scroll {
                    mask |= 0x01;
                }
                if num {
                    mask |= 0x02;
                }
                if caps {
                    mask |= 0x04;
                }
                if kana {
                    mask |= 0x08;
                }
                body.put_u8((0x03 << 5) | mask);
            }
        }
        // fpInputHeader = action(0) | numEvents(1) << 2 | flags(0)
        let total_len = 2 + body.len();
        let mut frame = BytesMut::with_capacity(total_len);
        frame.put_u8(1 << 2);
        frame.put_u8(total_len as u8);
        frame.extend_from_slice(&body);
        frame.to_vec()
    }
}

/// Observed `guac_rdp_disp_set_size @ 0xec75`: clamp `[200, 8192]` and align `width &= !1`.
#[must_use]
pub fn clamp_rdp_display_size(width: u32, height: u32) -> (u32, u32) {
    let w = width.clamp(200, 8192) & !1;
    let h = height.clamp(200, 8192);
    (w, h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_x224_cr_and_parses_cc() {
        let req = X224Request {
            cookie: "operator".into(),
            requested_protocols: NegotiationProtocol::HybridExNla.requested_protocols_mask(),
        };
        let bytes = req.encode();
        assert_eq!(bytes[0], TPKT_VERSION);
        assert_eq!(bytes[5], 0xE0);

        // Simulated Windows Server HYBRID_EX confirm
        let cc = [
            0x03, 0x00, 0x00, 0x13, // TPKT len 19
            0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // CC
            0x02, 0x0f, 0x08, 0x00, // RDP_NEG_RSP
            0x08, 0x00, 0x00, 0x00, // PROTOCOL_HYBRID_EX
        ];
        let parsed = X224Confirm::parse(&cc).unwrap();
        assert_eq!(parsed.selected_protocol, protocol_flags::HYBRID_EX);
    }

    #[test]
    fn clamps_and_even_aligns_rdp_resize() {
        assert_eq!(clamp_rdp_display_size(1921, 1081), (1920, 1081));
        assert_eq!(clamp_rdp_display_size(100, 9999), (200, 8192));
    }
}
