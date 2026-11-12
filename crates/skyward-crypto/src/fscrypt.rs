//! Letting a key into a filesystem, so the files it was used on can be
//! read. The kernel keeps the key for the filesystem, not for any one
//! file, and names it by a hash it works out itself.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha512};
use std::path::Path;

/// How long the name the kernel gives a key is.
pub const NAME_BYTES: usize = 16;

/// Let `raw` into the filesystem mounted at `mount`, and give the name the
/// kernel knows it by. Every file whose directory names that key can be
/// read from then on.
#[cfg(target_os = "android")]
pub fn add_key(
    mount: &Path,
    raw: &[u8],
    wrapped: bool,
    recorded: Option<&[u8]>,
) -> Result<[u8; NAME_BYTES]> {
    use std::os::fd::AsRawFd;
    /// The request's fixed part, before the key itself.
    const HEADER_BYTES: usize = 80;
    /// The key is named by an 8-byte descriptor chosen by the caller.
    const BY_DESCRIPTOR: u32 = 1;
    /// The key is named by a 16-byte identifier.
    const BY_IDENTIFIER: u32 = 2;
    /// The key is one only the storage hardware can unwrap.
    const HARDWARE_WRAPPED: u32 = 1;
    const ADD_KEY: u32 = 0xc050_6617;

    let mut arg = vec![0u8; HEADER_BYTES + raw.len()];
    let kind = match recorded {
        None => BY_IDENTIFIER,
        Some(recorded) => match recorded.len() {
            8 => BY_DESCRIPTOR,
            NAME_BYTES => BY_IDENTIFIER,
            n => bail!("a key is named by 8 or {NAME_BYTES} bytes, and the phone recorded {n}"),
        },
    };
    arg[0..4].copy_from_slice(&kind.to_ne_bytes());
    if let Some(recorded) = recorded {
        arg[8..8 + recorded.len()].copy_from_slice(recorded);
    }
    arg[40..44].copy_from_slice(&(raw.len() as u32).to_ne_bytes());
    if wrapped {
        arg[76..80].copy_from_slice(&HARDWARE_WRAPPED.to_ne_bytes());
    }
    arg[HEADER_BYTES..].copy_from_slice(raw);
    let dir = std::fs::File::open(mount).with_context(|| format!("open {}", mount.display()))?;
    if unsafe { libc::ioctl(dir.as_raw_fd(), ADD_KEY as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("let a key into {}", mount.display()));
    }
    let mut name = [0u8; NAME_BYTES];
    name.copy_from_slice(&arg[8..8 + NAME_BYTES]);
    Ok(name)
}

/// Whether the names and contents under `dir` read as they are: it is not
/// encrypted, or the key it is encrypted with is in the kernel. A user's
/// own files read only once that user's key is let in.
#[cfg(target_os = "android")]
pub fn unlocked(dir: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    const GET_POLICY: u32 = 0xc009_6616;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    /// How the first kind of policy names its key, and how the second does.
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// The second kind of policy is the largest: its version, three bytes
    /// of how it encrypts, four reserved, and the key's name.
    const POLICY_BYTES: usize = 24;
    const PRESENT: u32 = 2;

    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut policy = [0u8; 8 + POLICY_BYTES];
    policy[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_POLICY as libc::Ioctl,
            policy.as_mut_ptr(),
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(true);
        }
        return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    let mut status = [0u8; 128];
    match policy[8] {
        0 => {
            status[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            status[8..16].copy_from_slice(&policy[12..20]);
        }
        2 => {
            status[..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
            status[8..8 + NAME_BYTES].copy_from_slice(&policy[16..16 + NAME_BYTES]);
        }
        other => bail!(
            "{} is encrypted under a policy of version {other}, which is not known here",
            dir.display()
        ),
    }
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_KEY_STATUS as libc::Ioctl,
            status.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("ask whether the key for {} is in", dir.display()));
    }
    Ok(u32::from_ne_bytes(status[64..68].try_into().expect("four bytes")) == PRESENT)
}

/// The descriptor or identifier of the encryption policy on `dir`, or none
/// where the directory is not encrypted.
#[cfg(target_os = "android")]
pub fn policy_ref(dir: &Path) -> Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    const GET_POLICY: u32 = 0xc009_6616;
    const POLICY_BYTES: usize = 24;

    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut policy = [0u8; 8 + POLICY_BYTES];
    policy[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_POLICY as libc::Ioctl,
            policy.as_mut_ptr(),
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    match policy[8] {
        0 => Ok(Some(policy[12..20].to_vec())),
        2 => Ok(Some(policy[16..32].to_vec())),
        other => bail!(
            "{} is encrypted under a policy of version {other}, which is not known here",
            dir.display()
        ),
    }
}

/// Whether what a phone says about how it encrypts its files means the
/// keys are ones only the storage hardware can unwrap.
pub fn hardware_wrapped(mode: &str) -> bool {
    mode.split(['+', ':']).any(|part| part == "wrappedkey_v0")
}

/// The fscrypt policy version a phone's mode string names.
pub fn policy_version(mode: &str) -> u32 {
    mode.split(['+', ':'])
        .find_map(|part| part.strip_prefix('v').and_then(|n| n.parse().ok()))
        .unwrap_or(2)
}

/// The 8-byte descriptor Android's v1 policies use for `raw`: the first
/// eight bytes of SHA-512 applied twice.
pub fn key_descriptor(raw: &[u8]) -> [u8; 8] {
    let once = Sha512::digest(raw);
    let twice = Sha512::digest(once);
    twice[..8].try_into().expect("eight bytes")
}

/// Read the name the phone recorded for a key it let in, to check against
/// the name the kernel works out now.
pub fn recorded_name(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match raw.len() {
        8 | NAME_BYTES => Ok(raw),
        n => bail!(
            "{} holds {n} bytes, and a key's name is 8 or {NAME_BYTES}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_says_whether_the_hardware_holds_the_keys() {
        assert!(hardware_wrapped(
            "aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"
        ));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2"));
        assert!(!hardware_wrapped(
            "aes-256-xts:aes-256-cts:v2+wrappedkey_v1"
        ));
        assert_eq!(policy_version("ice:aes-256-cts:v1+wrappedkey_v0"), 1);
        assert_eq!(policy_version("aes-256-xts:aes-256-cts:v2"), 2);
    }

    #[test]
    fn a_name_is_read_back_only_at_its_own_length() {
        let dir = std::env::temp_dir().join(format!("skyward-fscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("ref");
        std::fs::write(&good, [7u8; NAME_BYTES]).unwrap();
        assert_eq!(recorded_name(&good).unwrap(), [7u8; NAME_BYTES]);
        let descriptor = dir.join("ref-v1");
        std::fs::write(&descriptor, [8u8; 8]).unwrap();
        assert_eq!(recorded_name(&descriptor).unwrap(), [8u8; 8]);
        let short = dir.join("short");
        std::fs::write(&short, vec![7u8; NAME_BYTES - 1]).unwrap();
        assert!(recorded_name(&short).is_err());
    }
}
