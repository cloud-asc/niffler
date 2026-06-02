use ssh_key::PrivateKey;
use ssh_key::private::KeypairData;

#[derive(Debug)]
pub struct KeyFinding {
    pub key_type: String,
    pub is_encrypted: bool,
    pub bits: Option<usize>,
}

/// Check if data contains an OpenSSH private key.
/// Returns key metadata if found, None otherwise.
#[must_use]
pub fn check_ssh_key(data: &[u8]) -> Option<KeyFinding> {
    let text = std::str::from_utf8(data).ok()?;
    let key = PrivateKey::from_openssh(text).ok()?;

    let bits = match key.key_data() {
        KeypairData::Ed25519(_) => Some(256),
        _ => None,
    };

    Some(KeyFinding {
        key_type: key.algorithm().to_string(),
        is_encrypted: key.is_encrypted(),
        bits,
    })
}

/// Check if data contains an X.509 private key (PEM format) or DER certificate.
#[must_use]
pub fn check_x509_for_private_key(data: &[u8]) -> Option<KeyFinding> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
        && text.contains("PRIVATE KEY")
    {
        // Detect encrypted private keys:
        // - PKCS#8:  "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        // - PKCS#1:  "Proc-Type: 4,ENCRYPTED" header in PEM body
        let is_encrypted = text.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED");
        return Some(KeyFinding {
            key_type: "X.509 Private Key".into(),
            is_encrypted,
            bits: None,
        });
    }

    // DER certificate detection intentionally omitted: public CA certificates
    // should not be flagged as private key findings. The classifier's file-name
    // rules already handle .der/.crt files separately.

    None
}

/// Check if data contains a PGP private key block.
///
/// Encryption is determined by dearmoring the block and inspecting the
/// secret-key packet's S2K-usage octet. When the packet can't be parsed
/// (truncated, unsupported version), `is_encrypted` defaults to `false`,
/// which maps to the higher-severity Black triage in `scan_file()`.
#[must_use]
pub fn check_pgp_key(data: &[u8]) -> Option<KeyFinding> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return None;
    }
    let is_encrypted = dearmor_pgp(text)
        .and_then(|packets| secret_key_is_encrypted(&packets))
        .unwrap_or(false);
    Some(KeyFinding {
        key_type: "PGP Private Key".into(),
        is_encrypted,
        bits: None,
    })
}

/// Extract and base64-decode the body of a PGP private-key armor block.
fn dearmor_pgp(text: &str) -> Option<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    const END: &str = "-----END PGP PRIVATE KEY BLOCK-----";
    let start = text.find(BEGIN)? + BEGIN.len();
    let rest = &text[start..];
    let stop = rest.find(END)?;
    let mut b64 = String::new();
    for line in rest[..stop].lines() {
        let line = line.trim();
        if line.is_empty() || line.contains(':') || line.starts_with('=') {
            continue; // blank, armor header, or CRC line
        }
        b64.push_str(line);
    }
    base64_decode(&b64)
}

/// Decode standard base64 (RFC 4648), ignoring whitespace and padding.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        buf = (buf << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Parse the first packet; if it's a Secret-Key (tag 5) or Secret-Subkey (tag 7),
/// return whether its S2K-usage octet marks the key as encrypted.
///
/// Returns `None` when the packet isn't a secret key or can't be confidently parsed.
fn secret_key_is_encrypted(b: &[u8]) -> Option<bool> {
    let mut pos = 0usize;
    let first = *b.first()?;
    pos += 1;
    if first & 0x80 == 0 {
        return None;
    }
    let new_format = first & 0x40 != 0;
    let tag = if new_format {
        first & 0x3F
    } else {
        (first >> 2) & 0x0F
    };
    if tag != 5 && tag != 7 {
        return None;
    }
    // Skip the length header — fields are read positionally.
    if new_format {
        let l0 = *b.get(pos)?;
        pos += 1;
        if l0 < 192 {
        } else if l0 < 224 {
            pos += 1;
        } else if l0 == 255 {
            pos += 4;
        } else {
            return None; // partial body length unsupported
        }
    } else {
        match first & 0x03 {
            0 => pos += 1,
            1 => pos += 2,
            2 => pos += 4,
            _ => return None, // indeterminate length
        }
    }
    if pos > b.len() {
        return None;
    }
    let version = *b.get(pos)?;
    pos += 1;
    if version != 3 && version != 4 {
        return None; // v3/v4 only; v5/v6 layout differs
    }
    pos += 4; // creation time
    if version == 3 {
        pos += 2; // validity period
    }
    let algo = *b.get(pos)?;
    pos += 1;
    skip_public_key_material(b, &mut pos, algo)?;
    Some(*b.get(pos)? != 0)
}

/// Advance `pos` past one MPI (2-octet bit length + ceil(bits/8) bytes).
fn skip_mpi(b: &[u8], pos: &mut usize) -> Option<()> {
    let bits = (usize::from(*b.get(*pos)?) << 8) | usize::from(*b.get(*pos + 1)?);
    *pos += 2 + bits.div_ceil(8);
    (*pos <= b.len()).then_some(())
}

/// Advance `pos` past a curve OID (1-octet length + OID bytes).
fn skip_ecc_oid(b: &[u8], pos: &mut usize) -> Option<()> {
    let len = usize::from(*b.get(*pos)?);
    if len == 0 || len == 0xFF {
        return None; // reserved
    }
    *pos += 1 + len;
    (*pos <= b.len()).then_some(())
}

/// Advance `pos` past the public-key material for the given algorithm.
fn skip_public_key_material(b: &[u8], pos: &mut usize, algo: u8) -> Option<()> {
    match algo {
        1..=3 => {
            // RSA: n, e
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
        }
        16 | 20 => {
            // ElGamal: p, g, y
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
        }
        17 => {
            // DSA: p, q, g, y
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
            skip_mpi(b, pos)?;
        }
        18 => {
            // ECDH: OID, point MPI, KDF params
            skip_ecc_oid(b, pos)?;
            skip_mpi(b, pos)?;
            let klen = usize::from(*b.get(*pos)?);
            *pos += 1 + klen;
            if *pos > b.len() {
                return None;
            }
        }
        19 | 22 => {
            // ECDSA / EdDSA: OID, point MPI
            skip_ecc_oid(b, pos)?;
            skip_mpi(b, pos)?;
        }
        _ => return None,
    }
    Some(())
}

/// Try all key material inspectors in priority order: SSH → X.509 → PGP.
#[must_use]
pub fn inspect_key_material(data: &[u8]) -> Option<KeyFinding> {
    check_ssh_key(data)
        .or_else(|| check_x509_for_private_key(data))
        .or_else(|| check_pgp_key(data))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const UNENCRYPTED_ED25519_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

    pub(crate) const ENCRYPTED_ED25519_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBKH96ujW
umB6/WnTNPjTeaAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoFzvbvyFMhAiwBOXF0mhUUacPUCMZXivG2up2c
hEnAw1b6BLRPyWbY5cC2n9ggD4ivJ1zSts6sBgjyiXQAReyrP35myYvT/OIB/NpwZM/xIJ
N7MHSUzlkX4adBrga3f7GS4uv4ChOoxC4XsE5HsxtGsq1X8jzqLlZTmOcxkcEneYQexrUc
bQP0o+gL5aKK8cQgiIlXeDbRjqhc4+h4EF6lY=
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn ssh_key_unencrypted_detected() {
        let result = check_ssh_key(UNENCRYPTED_ED25519_KEY.as_bytes());
        let finding = result.expect("should detect unencrypted key");
        assert!(!finding.is_encrypted);
        assert!(!finding.key_type.is_empty());
        assert!(finding.key_type.contains("ed25519"));
        assert_eq!(finding.bits, Some(256));
    }

    #[test]
    fn ssh_key_encrypted_detected() {
        let result = check_ssh_key(ENCRYPTED_ED25519_KEY.as_bytes());
        let finding = result.expect("should detect encrypted key");
        assert!(finding.is_encrypted);
        assert!(finding.key_type.contains("ed25519"));
    }

    #[test]
    fn ssh_key_invalid_data_returns_none() {
        assert!(check_ssh_key(b"This is not an SSH key").is_none());
    }

    #[test]
    fn ssh_key_empty_data_returns_none() {
        assert!(check_ssh_key(b"").is_none());
    }

    #[test]
    fn ssh_key_public_key_returns_none() {
        let pubkey = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILtMSEnZH0GU89zP user@host";
        assert!(check_ssh_key(pubkey).is_none());
    }

    #[test]
    fn x509_pem_private_key_detected() {
        let data = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect private key");
        assert!(!finding.is_encrypted);
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_pem_encrypted_private_key_detected() {
        let data =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFH...\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let finding =
            check_x509_for_private_key(data).expect("should detect encrypted private key");
        assert!(finding.is_encrypted);
    }

    #[test]
    fn x509_pem_rsa_private_key_detected() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect RSA private key");
        assert!(!finding.is_encrypted);
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_pem_ec_private_key_detected() {
        let data = b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...\n-----END EC PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect EC private key");
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_pem_pkcs1_encrypted_via_proc_type() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,...\n\nMIIEow...\n-----END RSA PRIVATE KEY-----\n";
        let finding =
            check_x509_for_private_key(data).expect("should detect PKCS#1 encrypted private key");
        assert!(
            finding.is_encrypted,
            "Proc-Type: 4,ENCRYPTED should be detected as encrypted"
        );
    }

    #[test]
    fn x509_plain_text_returns_none() {
        assert!(check_x509_for_private_key(b"Just some random text").is_none());
    }

    #[test]
    fn x509_pem_certificate_only() {
        let data = b"-----BEGIN CERTIFICATE-----\nMIIDXTCCA...\n-----END CERTIFICATE-----\n";
        assert!(
            check_x509_for_private_key(data).is_none(),
            "cert-only should return None — classifier handles via rules"
        );
    }

    #[test]
    fn pgp_private_key_detected() {
        let data = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----\n";
        let finding = check_pgp_key(data).expect("should detect PGP private key");
        assert!(finding.key_type.contains("PGP"));
    }

    #[test]
    fn pgp_public_key_not_detected() {
        let data = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmQENBF...\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert!(check_pgp_key(data).is_none());
    }

    #[test]
    fn pgp_no_match_on_plain_text() {
        assert!(check_pgp_key(b"Not a PGP key").is_none());
    }

    #[test]
    fn pgp_unparseable_defaults_unencrypted() {
        // Garbage armor body can't be parsed into packets; conservatively report
        // unencrypted (the higher-severity triage) rather than guessing.
        let data = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----\n";
        let finding = check_pgp_key(data).expect("should detect PGP key");
        assert!(!finding.is_encrypted);
    }

    fn b64_encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            out.push(A[(b[0] >> 2) as usize] as char);
            out.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                A[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[(b[2] & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn armor_private_key(packet: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{}\n-----END PGP PRIVATE KEY BLOCK-----\n",
            b64_encode(packet)
        )
        .into_bytes()
    }

    /// New-format Secret-Key packet (tag 5), v4 RSA, with the given S2K-usage octet.
    fn rsa_v4_secret_key(usage: u8) -> Vec<u8> {
        let body = [
            0x04, // version 4
            0x00, 0x00, 0x00, 0x00, // creation time
            0x01, // algo: RSA
            0x00, 0x08, 0x01, // MPI n: 8 bits -> 1 byte
            0x00, 0x08, 0x01, // MPI e: 8 bits -> 1 byte
            usage,
        ];
        let mut packet = vec![0xC5, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    /// New-format Secret-Key packet (tag 5), v4 EdDSA (has an ECC OID), with usage octet.
    fn eddsa_v4_secret_key(usage: u8) -> Vec<u8> {
        let mut body = vec![
            0x04, // version 4
            0x00, 0x00, 0x00, 0x00, // creation time
            0x16, // algo: EdDSA (22)
            0x09, // OID length
            0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, // Ed25519 OID
            0x00, 0x08, 0x01, // MPI point: 8 bits -> 1 byte
        ];
        body.push(usage);
        let mut packet = vec![0xC5, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn pgp_rsa_v4_unencrypted_detected() {
        let data = armor_private_key(&rsa_v4_secret_key(0x00));
        let finding = check_pgp_key(&data).expect("should detect PGP key");
        assert!(!finding.is_encrypted, "usage octet 0 means unencrypted");
    }

    #[test]
    fn pgp_rsa_v4_encrypted_detected() {
        for usage in [0xFE_u8, 0xFF, 0x09] {
            let data = armor_private_key(&rsa_v4_secret_key(usage));
            let finding = check_pgp_key(&data).expect("should detect PGP key");
            assert!(
                finding.is_encrypted,
                "usage octet {usage:#x} means encrypted"
            );
        }
    }

    #[test]
    fn pgp_eddsa_v4_encrypted_detected() {
        let data = armor_private_key(&eddsa_v4_secret_key(0xFF));
        let finding = check_pgp_key(&data).expect("should detect PGP key");
        assert!(finding.is_encrypted, "EdDSA with usage 0xFF is encrypted");
    }

    #[test]
    fn pgp_eddsa_v4_unencrypted_detected() {
        let data = armor_private_key(&eddsa_v4_secret_key(0x00));
        let finding = check_pgp_key(&data).expect("should detect PGP key");
        assert!(!finding.is_encrypted);
    }
}
