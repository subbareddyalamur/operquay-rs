# RDP & VNC Protocol Contracts

## Clean-Room Constraint
- **Strictly zero `ironrdp*` implementation dependencies**. Check with `cargo tree --workspace | grep -i ironrdp`.

## Key Reverse-Engineered Invariants Preserved in Rust
- Guacamole display complexity heuristic (`libguac.so @ 0xeacf`): `(identical_runs * 256) / max(1, transitions) - 1024`; `>= 0` -> PNG, `< 0` & `fps > 2` & `area > 4096` -> JPEG.
- Quality formula (`0xebd4`): `lag <= 19 ? 90 : max(30, 110 - lag)`.
- RDP resize (`libguac-client-rdp.so @ 0xec75`): clamp `[200, 8192]` and force even `width &= !1`.
- RDP 25 keymaps (`@ 0x4e640`): `base`, `base_altgr`, `failsafe`, + 22 Windows LCIDs (0x0409..0x041f), dead-key composition + Unicode fallback (`0x16250`).
- Binary `operquay-rdp-v2` (`OQR2`) wire magic `[0x4F, 0x51, 0x52, 0x32]` removes 33% base64 bloat, carries async `CursorShape`/`CursorMove` for zero-RTT pointer prediction, and leaves legacy `"guacamole"` subprotocol intact.
- VNC (`RFC 6143`): DES key bit-reversal on each byte of 8-byte VNCAuth challenge key, `SetDesktopSize (0xfb)`, `Raw`/`CopyRect`/`Cursor`.

