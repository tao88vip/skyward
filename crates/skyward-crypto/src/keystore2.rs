//! Reading what the phone's key service was asked to keep. The service
//! holds each key under a name, and what it holds is the handle the secure
//! world knows the key by.

use anyhow::{Context, Result};
use std::path::Path;

/// Where the key service keeps what it was asked to keep.
pub const DATABASE: &str = "/data/misc/keystore/persistent.sqlite";

/// Android 11 and earlier keep one file per entry under a directory for the
/// Android user. The system server, which owns the synthetic-password keys,
/// writes as uid 1000.
const LEGACY_ROOT: &str = "/data/misc/keystore";
const SYSTEM_UID: u32 = 1000;

/// The kind of thing a row holds: the key itself rather than a certificate.
const KEY_BLOB: i64 = 0;

/// The common header of a Keystore 1 file: version, type, flags and the
/// salt size, then the IV, authentication tag, and big-endian value length.
const LEGACY_HEADER_BYTES: usize = 40;
const LEGACY_VERSION: u8 = 3;
const LEGACY_KM_BLOB: u8 = 4;
const LEGACY_ENCRYPTED: u8 = 1;
const LEGACY_SUPER_ENCRYPTED: u8 = 1 << 2;

/// The handle the secure world knows the key named `alias` by. The
/// database is opened as it lies, without being written to or waiting on
/// anyone, since the phone it belongs to is not running.
pub fn key_blob(database: &Path, alias: &str) -> Result<Vec<u8>> {
    key_blob_for_user(database, alias, 0)
}

/// Read a key owned by the system server for Android user `user`, from the
/// database Android 12 introduced or from Keystore 1's per-entry files on
/// Android 11 and earlier.
pub fn key_blob_for_user(database: &Path, alias: &str, user: u32) -> Result<Vec<u8>> {
    if !database.is_file() {
        return legacy_key_blob(user, alias);
    }
    let at = format!("file:{}?immutable=1", database.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let db = rusqlite::Connection::open_with_flags(&at, flags)
        .with_context(|| format!("open {}", database.display()))?;
    let mut query = db
        .prepare(
            "SELECT b.blob FROM blobentry b JOIN keyentry k ON b.keyentryid = k.id
             WHERE k.alias = ?1 AND b.subcomponent_type = ?2 ORDER BY b.id DESC LIMIT 1",
        )
        .context("ask the key service's store for a key")?;
    let mut rows = query
        .query((alias, KEY_BLOB))
        .context("ask the key service's store for a key")?;
    let row = rows
        .next()
        .with_context(|| format!("read what {} says about {alias}", database.display()))?
        .with_context(|| format!("{} holds no key named {alias}", database.display()))?;
    row.get(0)
        .with_context(|| format!("read the key named {alias}"))
}

fn legacy_key_blob(user: u32, alias: &str) -> Result<Vec<u8>> {
    let encoded = encode_alias(alias);
    let dir = Path::new(LEGACY_ROOT).join(format!("user_{user}"));
    let mut tried = Vec::new();
    for prefix in ["USRPKEY", "USRSKEY"] {
        let path = dir.join(format!("{SYSTEM_UID}_{prefix}_{encoded}"));
        tried.push(path.clone());
        match std::fs::read(&path) {
            Ok(raw) => {
                return legacy_blob(&raw)
                    .with_context(|| format!("read the key named {alias} in {}", path.display()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        }
    }
    anyhow::bail!(
        "{} and {} hold no key named {alias}",
        tried[0].display(),
        tried[1].display()
    )
}

fn legacy_blob(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        raw.len() >= LEGACY_HEADER_BYTES,
        "a Keystore 1 entry is {} bytes, and its header alone is {LEGACY_HEADER_BYTES}",
        raw.len()
    );
    anyhow::ensure!(
        raw[0] == LEGACY_VERSION,
        "a Keystore 1 entry is in version {}, and Skyward reads version {LEGACY_VERSION}",
        raw[0]
    );
    anyhow::ensure!(
        raw[1] == LEGACY_KM_BLOB,
        "a Keystore 1 entry has type {}, and a key blob is type {LEGACY_KM_BLOB}",
        raw[1]
    );
    anyhow::ensure!(
        raw[2] & (LEGACY_ENCRYPTED | LEGACY_SUPER_ENCRYPTED) == 0,
        "the Keystore 1 key is wrapped by a master key, not by Keymaster alone"
    );
    let length = u32::from_be_bytes(raw[36..40].try_into().expect("four bytes")) as usize;
    let end = LEGACY_HEADER_BYTES
        .checked_add(length)
        .context("the Keystore 1 key length overflows")?;
    anyhow::ensure!(
        end <= raw.len(),
        "a Keystore 1 entry names {length} bytes of key but holds {}",
        raw.len().saturating_sub(LEGACY_HEADER_BYTES)
    );
    Ok(raw[LEGACY_HEADER_BYTES..end].to_vec())
}

/// Keystore 1 leaves printable bytes alone and turns every other byte into
/// two printable characters.
fn encode_alias(alias: &str) -> String {
    let mut out = String::new();
    for byte in alias.bytes() {
        if (b'0'..=b'~').contains(&byte) {
            out.push(byte as char);
        } else {
            out.push((b'+' + (byte >> 6)) as char);
            out.push((b'0' + (byte & 0x3f)) as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(flags: u8, value: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; LEGACY_HEADER_BYTES];
        raw[0] = LEGACY_VERSION;
        raw[1] = LEGACY_KM_BLOB;
        raw[2] = flags;
        raw[36..40].copy_from_slice(&(value.len() as u32).to_be_bytes());
        raw.extend_from_slice(value);
        raw
    }

    #[test]
    fn a_critical_keymaster_blob_is_the_value_after_the_header() {
        assert_eq!(legacy_blob(&blob(8, b"KMK\0key")).unwrap(), b"KMK\0key");
    }

    #[test]
    fn encrypted_or_short_entries_are_refused() {
        assert!(legacy_blob(&blob(LEGACY_ENCRYPTED, b"key")).is_err());
        assert!(legacy_blob(&blob(LEGACY_SUPER_ENCRYPTED, b"key")).is_err());
        let mut cut = blob(8, b"key");
        cut[39] = 4;
        assert!(legacy_blob(&cut).is_err());
        assert!(legacy_blob(&[3, 4, 8]).is_err());
    }

    #[test]
    fn printable_aliases_are_not_changed() {
        let alias = "synthetic_password_6bf28c4e0f5fa470";
        assert_eq!(encode_alias(alias), alias);
    }
}
