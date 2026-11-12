use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0, HeaderV0Versioned};
use anyhow::{anyhow, ensure, Context, Result};
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;

/// A boot image (`boot`, `init_boot`, `recovery`) split into its header,
/// kernel, ramdisk and the sections after the ramdisk.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    /// What follows the page-aligned ramdisk. Versions 0 through 2 keep the
    /// second-stage bootloader, recovery DTBO/ACPIO and, in version 2, the
    /// DTB here, together with their page padding. Versions 3 and 4 have
    /// none.
    pub tail: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes
        .get(at..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        ensure!(
            header.page_size() > 0,
            "the boot image names a page size of zero"
        );
        let kernel = section(
            bytes,
            header.kernel_position(),
            header.kernel_size(),
            "kernel",
        )?;
        let ramdisk = section(
            bytes,
            header.ramdisk_position(),
            header.ramdisk_size(),
            "ramdisk",
        )?;
        let tail = match &header {
            Header::V0(h) => {
                let start = h.second_bootloader_position();
                section(
                    bytes,
                    start,
                    u32::try_from(image_end(h)? - start)?,
                    "sections after the ramdisk",
                )?
            }
            Header::V3(_) => Vec::new(),
        };
        Ok(BootImage {
            header,
            kernel,
            ramdisk,
            tail,
        })
    }

    /// The image with sizes taken from its parts, in the same header version
    /// and page layout. A version 4 header keeps its version but carries no
    /// boot signature; unlocked bootloaders do not ask for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        let kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        let ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        let size_after_ramdisk = match &mut header {
            Header::V0(h) => {
                h.kernel_size = kernel_size;
                h.ramdisk_size = ramdisk_size;
                let recovery_dtbo_offset = h.recovery_dtbo_position() as u64;
                match &mut h.versioned {
                    HeaderV0Versioned::V0 => {}
                    HeaderV0Versioned::V1 {
                        recovery_dtbo_addr, ..
                    }
                    | HeaderV0Versioned::V2 {
                        recovery_dtbo_addr, ..
                    } => {
                        *recovery_dtbo_addr = recovery_dtbo_offset;
                    }
                }
                h.hash_digest = boot_id(&self.kernel, &self.ramdisk, &self.tail, h)?;
                let start = h.second_bootloader_position();
                Some(image_end(h)? - start)
            }
            Header::V3(h) => {
                h.kernel_size = kernel_size;
                h.ramdisk_size = ramdisk_size;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
                None
            }
        };
        ensure!(
            size_after_ramdisk.is_none_or(|size| size == self.tail.len()),
            "the sections after the ramdisk are {} bytes, where the boot image header describes {}",
            self.tail.len(),
            size_after_ramdisk.unwrap_or_default()
        );
        let mut out = Vec::new();
        let page = header.page_size();
        header.write(&mut out).context("write header")?;
        pad(&mut out, page);
        out.extend_from_slice(&self.kernel);
        pad(&mut out, page);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(&self.tail);
        if let Header::V0(h) = &header {
            ensure!(
                out.len() == image_end(h)?,
                "the image is {} bytes, where its header describes {}",
                out.len(),
                image_end(h)?
            );
        }
        Ok(out)
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}

/// The SHA-1 the version 0 through 2 header carries over its parts. The
/// recovery DTBO and, where there is one, DTB follow the next page boundary
/// after the second-stage bootloader.
fn boot_id(kernel: &[u8], ramdisk: &[u8], tail: &[u8], header: &HeaderV0) -> Result<[u8; 32]> {
    let page = header.page_size as usize;
    ensure!(page > 0, "the boot image names a page size of zero");
    let aligned = |size: usize| size.div_ceil(page) * page;
    let take = |at: usize, size: u32| {
        tail.get(at..at + size as usize).with_context(|| {
            format!("{size} bytes at {at} run past the sections after the ramdisk")
        })
    };

    let second_size = header.second_bootloader_size;
    let second = take(0, second_size)?;
    let dtbo_at = aligned(second_size as usize);
    let (dtbo, dtb_at, dtb_size) = match header.versioned {
        HeaderV0Versioned::V0 => (&[][..], dtbo_at, 0),
        HeaderV0Versioned::V1 {
            recovery_dtbo_size, ..
        } => {
            let dtbo = take(dtbo_at, recovery_dtbo_size)?;
            (dtbo, dtbo_at + aligned(recovery_dtbo_size as usize), 0)
        }
        HeaderV0Versioned::V2 {
            recovery_dtbo_size,
            dtb_size,
            ..
        } => {
            let dtbo = take(dtbo_at, recovery_dtbo_size)?;
            let dtb_at = dtbo_at + aligned(recovery_dtbo_size as usize);
            (dtbo, dtb_at, dtb_size)
        }
    };
    let dtb = take(dtb_at, dtb_size)?;

    let mut parts = vec![kernel, ramdisk, second];
    if !matches!(header.versioned, HeaderV0Versioned::V0) {
        parts.push(dtbo);
    }
    if matches!(header.versioned, HeaderV0Versioned::V2 { .. }) {
        parts.push(dtb);
    }
    let mut hash = Sha1::new();
    for part in parts {
        hash.update(part);
        hash.update((part.len() as u32).to_le_bytes());
    }
    let digest = hash.finalize();
    let mut out = [0; 32];
    out[..digest.len()].copy_from_slice(&digest);
    Ok(out)
}

/// Where a version 0 through 2 image ends. The dependency's
/// `HeaderV0::boot_image_size` leaves the second-stage section's padding out
/// of its version 1 and 2 calculation, so follow the header specification
/// here instead.
fn image_end(header: &HeaderV0) -> Result<usize> {
    let page = header.page_size as usize;
    ensure!(page > 0, "the boot image names a page size of zero");
    let aligned = |size: usize| size.div_ceil(page) * page;
    let recovery_dtbo = header.recovery_dtbo_position();
    Ok(match header.versioned {
        HeaderV0Versioned::V0 => recovery_dtbo,
        HeaderV0Versioned::V1 {
            recovery_dtbo_size, ..
        } => recovery_dtbo + aligned(recovery_dtbo_size as usize),
        HeaderV0Versioned::V2 {
            recovery_dtbo_size,
            dtb_size,
            ..
        } => recovery_dtbo + aligned(recovery_dtbo_size as usize) + aligned(dtb_size as usize),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abootimg_oxide::{HeaderV0, HeaderV0Versioned, OsVersionPatch};

    fn v1_image(ramdisk: &[u8]) -> Vec<u8> {
        let page = 4096usize;
        let kernel = b"kernel";
        let second = b"second";
        let recovery_dtbo = b"recovery dtbo";
        let aligned = |size: usize| size.div_ceil(page) * page;
        let recovery_dtbo_offset =
            page + aligned(kernel.len()) + aligned(ramdisk.len()) + aligned(second.len());
        let mut digest = Sha1::new();
        for part in [kernel, ramdisk, second, recovery_dtbo] {
            digest.update(part);
            digest.update((part.len() as u32).to_le_bytes());
        }
        let mut hash_digest = [0; 32];
        hash_digest[..20].copy_from_slice(&digest.finalize());
        let header = Header::V0(HeaderV0 {
            kernel_size: kernel.len() as u32,
            kernel_addr: 0,
            ramdisk_size: ramdisk.len() as u32,
            ramdisk_addr: 0,
            second_bootloader_size: second.len() as u32,
            second_bootloader_addr: 0,
            tags_addr: 0,
            page_size: page as u32,
            osversionpatch: OsVersionPatch(0),
            board_name: [0; 16],
            hash_digest,
            cmdline: Box::new([0; 1536]),
            versioned: HeaderV0Versioned::V1 {
                recovery_dtbo_size: recovery_dtbo.len() as u32,
                recovery_dtbo_addr: recovery_dtbo_offset as u64,
            },
        });
        let mut out = Vec::new();
        header.write(&mut out).unwrap();
        pad(&mut out, page);
        out.extend_from_slice(kernel);
        pad(&mut out, page);
        out.extend_from_slice(ramdisk);
        pad(&mut out, page);
        out.extend_from_slice(second);
        pad(&mut out, page);
        out.extend_from_slice(recovery_dtbo);
        pad(&mut out, page);
        out
    }

    #[test]
    fn version_1_keeps_the_second_stage_and_recovery_dtbo_exactly() {
        let original = v1_image(b"ramdisk");
        let image = BootImage::parse(&original).unwrap();
        assert_eq!(image.header.header_version(), 1);
        assert_eq!(image.kernel, b"kernel");
        assert_eq!(image.ramdisk, b"ramdisk");
        assert!(image.tail.windows(6).any(|w| w == b"second"));
        assert!(image.tail.windows(13).any(|w| w == b"recovery dtbo"));
        let made = image.to_bytes().unwrap();
        assert_eq!(&made[..576], &original[..576], "the header before its id");
        assert_eq!(&made[576..596], &original[576..596], "the id");
        assert_eq!(
            &made[608..],
            &original[608..],
            "the header after its id and all sections"
        );
    }

    #[test]
    fn a_version_1_ramdisk_that_changes_keeps_what_comes_after_it() {
        let original = v1_image(b"old ramdisk");
        let mut image = BootImage::parse(&original).unwrap();
        image.ramdisk = b"a longer ramdisk than before".to_vec();
        let made = image.to_bytes().unwrap();
        let back = BootImage::parse(&made).unwrap();
        assert_eq!(back.ramdisk, image.ramdisk);
        assert_eq!(back.tail, image.tail);
        assert_eq!(back.header.header_version(), 1);
        assert_eq!(made.len() % 4096, 0);
        let Header::V0(header) = &back.header else {
            panic!("version 1")
        };
        let HeaderV0Versioned::V1 {
            recovery_dtbo_addr, ..
        } = header.versioned
        else {
            panic!("version 1")
        };
        assert_eq!(recovery_dtbo_addr as usize, header.recovery_dtbo_position());
    }
}
