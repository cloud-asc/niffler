//! Pure formatting helpers for the shell (ls -l lines, file-handle hex).

use std::fmt::Write as _;

use crate::nfs::{DirEntry, NfsFh, NfsFileType};

/// Render a 10-char `ls`-style mode string, e.g. `-rw-r--r--`.
pub fn mode_string(ft: NfsFileType, mode: u32) -> String {
    let type_char = match ft {
        NfsFileType::Directory => 'd',
        NfsFileType::Symlink => 'l',
        NfsFileType::Regular => '-',
        NfsFileType::Other => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(type_char);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    s
}

/// Render one `ls -l` line: `<mode> <uid> <gid> <size> <name>`.
pub fn long_line(entry: &DirEntry) -> String {
    let a = &entry.attrs;
    format!(
        "{} {:>6} {:>6} {:>10} {}",
        mode_string(a.file_type, a.mode),
        a.uid,
        a.gid,
        a.size,
        entry.name
    )
}

/// Encode a file handle as lowercase hex.
pub fn handle_to_hex(fh: &NfsFh) -> String {
    let mut s = String::with_capacity(fh.as_bytes().len() * 2);
    for b in fh.as_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a lowercase/uppercase hex string into a file handle.
pub fn handle_from_hex(hex: &str) -> anyhow::Result<NfsFh> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("handle hex must have even length");
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(pair).map_err(|_| anyhow::anyhow!("invalid hex in handle"))?;
        let byte =
            u8::from_str_radix(s, 16).map_err(|_| anyhow::anyhow!("invalid hex in handle"))?;
        bytes.push(byte);
    }
    Ok(NfsFh::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::{DirEntry, NfsAttrs, NfsFh, NfsFileType};

    fn entry(name: &str, ft: NfsFileType, mode: u32, size: u64) -> DirEntry {
        DirEntry {
            name: name.into(),
            fh: NfsFh::new(vec![1, 2, 3]),
            attrs: NfsAttrs {
                file_type: ft,
                size,
                mode,
                uid: 1000,
                gid: 1000,
                mtime: 0,
            },
        }
    }

    #[test]
    fn mode_string_for_dir_rwxr_xr_x() {
        assert_eq!(mode_string(NfsFileType::Directory, 0o755), "drwxr-xr-x");
    }

    #[test]
    fn mode_string_for_file_0644() {
        assert_eq!(mode_string(NfsFileType::Regular, 0o644), "-rw-r--r--");
    }

    #[test]
    fn mode_string_for_symlink() {
        assert_eq!(mode_string(NfsFileType::Symlink, 0o777), "lrwxrwxrwx");
    }

    #[test]
    fn long_line_contains_fields() {
        let line = long_line(&entry("foo.txt", NfsFileType::Regular, 0o644, 1234));
        assert!(line.contains("-rw-r--r--"));
        assert!(line.contains("1000"));
        assert!(line.contains("1234"));
        assert!(line.ends_with("foo.txt"));
    }

    #[test]
    fn handle_hex_round_trips() {
        let fh = NfsFh::new(vec![0xAA, 0xBB, 0x01, 0xFF]);
        let hex = handle_to_hex(&fh);
        assert_eq!(hex, "aabb01ff");
        assert_eq!(handle_from_hex("aabb01ff").unwrap(), fh);
    }

    #[test]
    fn handle_from_hex_rejects_bad_input() {
        assert!(handle_from_hex("xyz").is_err());
        assert!(handle_from_hex("abc").is_err()); // odd length
    }
}
