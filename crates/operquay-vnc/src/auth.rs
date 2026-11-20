use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use des::Des;
use md5::{Digest as _, Md5};
use num_bigint::BigUint;
use zeroize::Zeroize;

/// RFC 6143 §7.2.2 VNC Authentication:
/// Pad/truncate password to 8 bytes, reverse bits within each byte, and DES-ECB encrypt
/// the 16-byte server challenge in two 8-byte blocks.
#[must_use]
pub fn encrypt_vnc_challenge(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (dst, &src) in key.iter_mut().zip(password.as_bytes().iter().take(8)) {
        *dst = src.reverse_bits();
    }

    let cipher = Des::new(GenericArray::from_slice(&key));
    key.zeroize();

    let mut out = *challenge;
    let mut b0 = GenericArray::clone_from_slice(&out[0..8]);
    let mut b1 = GenericArray::clone_from_slice(&out[8..16]);
    cipher.encrypt_block(&mut b0);
    cipher.encrypt_block(&mut b1);
    out[0..8].copy_from_slice(&b0);
    out[8..16].copy_from_slice(&b1);
    out
}

fn to_fixed_be(val: &BigUint, len: usize) -> Vec<u8> {
    let raw = val.to_bytes_be();
    if raw.len() >= len {
        return raw[raw.len() - len..].to_vec();
    }
    let mut padded = vec![0u8; len];
    padded[len - raw.len()..].copy_from_slice(&raw);
    padded
}

/// Apple Remote Desktop (`ARD`, RFB security type `30`) Diffie-Hellman + MD5 + AES-128-ECB
/// credential encryption (`M10.4`).
/// Returns `(client_public_key, encrypted_128_byte_credentials)`.
pub fn encrypt_apple_ard_credentials(
    generator: u16,
    prime_bytes: &[u8],
    peer_pub_bytes: &[u8],
    username: &str,
    password: &str,
) -> Result<(Vec<u8>, [u8; 128]), String> {
    let key_len = prime_bytes.len();
    if key_len == 0 || peer_pub_bytes.len() != key_len {
        return Err("invalid Apple ARD Diffie-Hellman key length".into());
    }
    let prime = BigUint::from_bytes_be(prime_bytes);
    if prime <= BigUint::from(1u8) {
        return Err("invalid Apple ARD DH modulus".into());
    }
    let peer_pub = BigUint::from_bytes_be(peer_pub_bytes);

    let mut priv_bytes = vec![0u8; key_len];
    getrandom::getrandom(&mut priv_bytes)
        .map_err(|e| format!("CSPRNG failure generating ARD DH exponent: {e}"))?;
    priv_bytes[0] |= 0x40;
    let priv_exp = BigUint::from_bytes_be(&priv_bytes);
    priv_bytes.zeroize();

    let client_pub = BigUint::from(generator).modpow(&priv_exp, &prime);
    let shared = peer_pub.modpow(&priv_exp, &prime);
    let mut shared_bytes = to_fixed_be(&shared, key_len);

    let mut aes_key: [u8; 16] = Md5::digest(&shared_bytes).into();
    shared_bytes.zeroize();

    let mut plain = [0u8; 128];
    let _ = getrandom::getrandom(&mut plain);
    let u_bytes = username.as_bytes();
    let u_len = u_bytes.len().min(63);
    plain[..u_len].copy_from_slice(&u_bytes[..u_len]);
    plain[u_len] = 0;

    let p_bytes = password.as_bytes();
    let p_len = p_bytes.len().min(63);
    plain[64..64 + p_len].copy_from_slice(&p_bytes[..p_len]);
    plain[64 + p_len] = 0;

    let cipher = Aes128::new(GenericArray::from_slice(&aes_key));
    aes_key.zeroize();

    let mut out = plain;
    plain.zeroize();
    for chunk in out.as_chunks_mut::<16>().0 {
        let mut blk = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut blk);
        chunk.copy_from_slice(&blk);
    }

    Ok((to_fixed_be(&client_pub, key_len), out))
}

#[cfg(test)]
mod tests {
    use cipher::BlockDecrypt as _;

    use super::*;

    #[test]
    fn bit_reverses_key_and_encrypts_challenge_deterministically() {
        let challenge = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ];
        let r1 = encrypt_vnc_challenge("secretpw", &challenge);
        let r2 = encrypt_vnc_challenge("secretpw", &challenge);
        let r3 = encrypt_vnc_challenge("wrongpw!", &challenge);
        assert_eq!(r1, r2);
        assert_ne!(r1, challenge);
        assert_ne!(r1, r3);
    }

    #[test]
    fn apple_ard_dh_md5_aes128_roundtrips_credentials() {
        // 64-byte RFC 3526-style safe modulus for fast unit verification
        let prime_bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68,
            0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08,
            0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A,
            0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        ];
        let generator = 5u16;
        let prime = BigUint::from_bytes_be(&prime_bytes);
        let srv_priv = BigUint::from(0x1234_5678_9abc_def1u64);
        let srv_pub = BigUint::from(generator).modpow(&srv_priv, &prime);
        let srv_pub_bytes = to_fixed_be(&srv_pub, prime_bytes.len());

        let (cli_pub_bytes, mut ct) = encrypt_apple_ard_credentials(
            generator,
            &prime_bytes,
            &srv_pub_bytes,
            "macops",
            "ArdSecret!42",
        )
        .unwrap();

        let shared_srv = BigUint::from_bytes_be(&cli_pub_bytes).modpow(&srv_priv, &prime);
        let shared_srv_bytes = to_fixed_be(&shared_srv, prime_bytes.len());
        let aes_key: [u8; 16] = Md5::digest(&shared_srv_bytes).into();
        let cipher = Aes128::new(GenericArray::from_slice(&aes_key));
        for chunk in ct.as_chunks_mut::<16>().0 {
            let mut blk = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut blk);
            chunk.copy_from_slice(&blk);
        }
        let u_end = ct[..64].iter().position(|&b| b == 0).unwrap();
        let p_end = ct[64..128].iter().position(|&b| b == 0).unwrap();
        assert_eq!(std::str::from_utf8(&ct[..u_end]).unwrap(), "macops");
        assert_eq!(
            std::str::from_utf8(&ct[64..64 + p_end]).unwrap(),
            "ArdSecret!42"
        );
    }
}
