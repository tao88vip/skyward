//! The footer a recovery image ends in for the bootloader to verify it by:
//! an unsigned vbmeta image holding the image's digest, laid out over the
//! whole partition as avbtool's `add_hash_footer --algorithm NONE` lays it.
//! An unlocked bootloader boots such an image whatever its digest; it gives
//! up on the whole slot when the footer at the partition's end points at
//! anything but a vbmeta image, as a stock footer left behind an image
//! written over the start of the partition does.

use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// The unit avbtool lays an image and its vbmeta image out in.
const BLOCK: usize = 4096;
const FOOTER_LEN: usize = 64;
const HEADER_LEN: usize = 256;
const TAG_HASH: u64 = 2;
const RELEASE: &[u8] = b"skyward-pack";

/// `image` grown to fill a `partition_size`-byte partition named
/// `partition`: the image, its vbmeta image from the next block on, and the
/// footer locating that in the partition's last bytes, zeros between.
pub fn footed(
    image: &[u8],
    partition: &str,
    partition_size: usize,
    salt: &[u8],
    inherited: &[u8],
) -> Result<Vec<u8>> {
    let digest = Sha256::new()
        .chain_update(salt)
        .chain_update(image)
        .finalize();
    let mut descriptors = hash_descriptor(image.len() as u64, partition, salt, &digest);
    descriptors.extend_from_slice(inherited);
    let vbmeta = vbmeta(&descriptors);
    let offset = image.len().next_multiple_of(BLOCK);
    let end = offset + vbmeta.len().next_multiple_of(BLOCK);
    ensure!(
        end + BLOCK <= partition_size,
        "a {}-byte image and its vbmeta image do not fit a {partition_size}-byte {partition} partition beside its footer",
        image.len()
    );
    let mut out = Vec::with_capacity(partition_size);
    out.extend_from_slice(image);
    out.resize(offset, 0);
    out.extend_from_slice(&vbmeta);
    out.resize(partition_size - FOOTER_LEN, 0);
    out.extend_from_slice(b"AVBf");
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    for n in [image.len(), offset, vbmeta.len()] {
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.resize(partition_size, 0);
    Ok(out)
}

/// The property descriptors in the vbmeta image at the end of `image`, copied
/// as they are. A bootloader reads the boot image's security patch from
/// them, and the secure world binds storage keys to the value it read.
pub fn inherited_properties(image: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(image)?;
    let length = file.seek(SeekFrom::End(0))?;
    ensure!(
        length >= FOOTER_LEN as u64,
        "{} is too short to hold an AVB footer",
        image.display()
    );
    file.seek(SeekFrom::Start(length - FOOTER_LEN as u64))?;
    let mut footer = [0u8; FOOTER_LEN];
    file.read_exact(&mut footer)?;
    ensure!(
        &footer[..4] == b"AVBf",
        "{} does not end in an AVB footer",
        image.display()
    );
    let vbmeta_offset = be64(&footer[20..28]);
    let vbmeta_size = be64(&footer[28..36]);
    ensure!(
        vbmeta_offset
            .checked_add(vbmeta_size)
            .is_some_and(|end| end <= length),
        "the AVB footer of {} names a vbmeta image outside it",
        image.display()
    );
    let mut vbmeta = vec![0u8; usize::try_from(vbmeta_size)?];
    file.seek(SeekFrom::Start(vbmeta_offset))?;
    file.read_exact(&mut vbmeta)?;
    ensure!(
        &vbmeta[..4] == b"AVB0",
        "the vbmeta image of {} has no AVB0 header",
        image.display()
    );
    let authentication = be64(&vbmeta[12..20]);
    let descriptors_offset = be64(&vbmeta[96..104]);
    let descriptors_size = be64(&vbmeta[104..112]);
    let start = 256u64
        .checked_add(authentication)
        .and_then(|n| n.checked_add(descriptors_offset))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the vbmeta image of {} has overflowed offsets",
                image.display()
            )
        })?;
    let end = start
        .checked_add(descriptors_size)
        .filter(|end| *end <= vbmeta.len() as u64)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the vbmeta image of {} has descriptors outside it",
                image.display()
            )
        })?;
    let descriptors = &vbmeta[start as usize..end as usize];
    let mut properties = Vec::new();
    let mut at = 0usize;
    while at < descriptors.len() {
        ensure!(
            at + 16 <= descriptors.len(),
            "the vbmeta image of {} has a cut descriptor",
            image.display()
        );
        let tag = be64(&descriptors[at..at + 8]);
        let following = be64(&descriptors[at + 8..at + 16]);
        let end = (at + 16)
            .checked_add(usize::try_from(following)?)
            .filter(|end| *end <= descriptors.len())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the vbmeta image of {} has a descriptor outside it",
                    image.display()
                )
            })?;
        if tag == 0 {
            properties.extend_from_slice(&descriptors[at..end]);
        }
        at = end;
    }
    Ok(properties)
}

fn be64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("eight bytes"))
}

/// A descriptor saying the first `image_size` bytes of `partition`, salted
/// with `salt`, hash to `digest` under SHA-256.
fn hash_descriptor(image_size: u64, partition: &str, salt: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut algorithm = [0u8; 32];
    algorithm[..6].copy_from_slice(b"sha256");
    let mut d = Vec::new();
    d.extend_from_slice(&TAG_HASH.to_be_bytes());
    // How many bytes follow these first sixteen, once they are known.
    d.extend_from_slice(&0u64.to_be_bytes());
    d.extend_from_slice(&image_size.to_be_bytes());
    d.extend_from_slice(&algorithm);
    // The lengths of the name, salt and digest, then the flags.
    for n in [partition.len(), salt.len(), digest.len(), 0] {
        d.extend_from_slice(&(n as u32).to_be_bytes());
    }
    d.extend_from_slice(&[0; 60]);
    d.extend_from_slice(partition.as_bytes());
    d.extend_from_slice(salt);
    d.extend_from_slice(digest);
    d.resize(d.len().next_multiple_of(8), 0);
    let following = (d.len() - 16) as u64;
    d[8..16].copy_from_slice(&following.to_be_bytes());
    d
}

/// An unsigned vbmeta image holding `descriptors`: its header, an empty
/// authentication block and the descriptors as its auxiliary block.
fn vbmeta(descriptors: &[u8]) -> Vec<u8> {
    let aux = descriptors.len().next_multiple_of(64);
    let mut v = Vec::with_capacity(HEADER_LEN + aux);
    v.extend_from_slice(b"AVB0");
    // The libavb version it needs, 1.0.
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u64.to_be_bytes());
    v.extend_from_slice(&(aux as u64).to_be_bytes());
    // No signing algorithm.
    v.extend_from_slice(&0u32.to_be_bytes());
    // The offsets and sizes of the hash, the signature, the public key, its
    // metadata and the descriptors, then the rollback index.
    let n = descriptors.len();
    for field in [0, 0, 0, 0, n, 0, n, 0, 0, n, 0] {
        v.extend_from_slice(&(field as u64).to_be_bytes());
    }
    // The flags and the rollback index location.
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(RELEASE);
    v.resize(HEADER_LEN, 0);
    v.extend_from_slice(descriptors);
    v.resize(HEADER_LEN + aux, 0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SALT: [u8; 32] = [0x5a; 32];

    /// What avbtool 1.4.0 makes of `len` bytes of `S`, given by
    /// `add_hash_footer --partition_size 81920 --partition_name recovery
    /// --algorithm NONE --salt 5a…5a --internal_release_string skyward-pack`.
    fn avbtool(len: usize) -> &'static [u8] {
        match len {
            4096 => include_bytes!("../tests/avb-footer-4096.bin"),
            1000 => include_bytes!("../tests/avb-footer-1000.bin"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn the_footer_is_avbtools_byte_for_byte() {
        for len in [4096, 1000] {
            let got = footed(&vec![b'S'; len], "recovery", 81920, &SALT, &[]).unwrap();
            assert!(got == avbtool(len), "a {len}-byte image");
        }
    }

    #[test]
    fn an_image_that_leaves_no_room_for_its_vbmeta_and_footer_is_refused() {
        let image = vec![b'S'; 8192];
        assert!(
            footed(&image, "recovery", 16384, &SALT, &[]).is_ok(),
            "a block each for the vbmeta image and the footer"
        );
        assert!(footed(&image, "recovery", 12288, &SALT, &[]).is_err());
    }

    #[test]
    fn property_descriptors_of_the_stock_image_are_kept() {
        let (key, value) = ("com.android.build.boot.security_patch", "2021-10-01");
        let mut property = Vec::new();
        property.extend_from_slice(&0u64.to_be_bytes());
        property.extend_from_slice(&0u64.to_be_bytes());
        property.extend_from_slice(&(key.len() as u64).to_be_bytes());
        property.extend_from_slice(&(value.len() as u64).to_be_bytes());
        property.extend_from_slice(key.as_bytes());
        property.push(0);
        property.extend_from_slice(value.as_bytes());
        property.resize(property.len().next_multiple_of(8), 0);
        let following = (property.len() - 16) as u64;
        property[8..16].copy_from_slice(&following.to_be_bytes());

        let image = footed(&vec![b'S'; 4096], "recovery", 81920, &SALT, &property).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&image).unwrap();
        assert_eq!(inherited_properties(file.path()).unwrap(), property);
    }
}
