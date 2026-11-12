# Xiaomi Mi 9 Pro 5G (crux) Feature and Test Status

Source version: `0.4.5`
Tested system: `V13.0.1.0.RFXCNXM` (Android 11)
Device layout: single-slot, non-A/B, no `init_boot`, no `super`

`0.4.5` adds the pre-operation backup and liability notices. The notices were
visually verified on the physical device in the `0.4.5` Recovery. Functional
hardware results below were established on the preceding `0.4.4` build; the
remaining `0.4.5` behavior is unchanged apart from these notices and CI fixes.

This branch is maintained for personal research and device testing. Stability,
compatibility, maintenance, release cadence, and future updates are not
guaranteed. See [FORK_NOTICE.md](FORK_NOTICE.md) and
[DISCLAIMER.md](DISCLAIMER.md).

Before any operation that changes a partition, back up and verify every
partition that may be written. The author and contributors accept no liability
for data loss, device damage or other loss.

## Status key

- **Verified on device**: completed on the current crux hardware.
- **Implemented, awaiting acceptance**: code, build, and unit tests pass, but
  the complete hardware workflow has not been exercised.
- **Partial**: limited by package format, hardware, or an unsupported flow.
- **Unsupported / not applicable**: not provided by the current architecture,
  or requires partitions this device does not have.

## Verified on device

| Feature | Result |
| --- | --- |
| Recovery flash and boot | Repeatedly flashed to `recovery` and booted |
| Display, touch, power and volume keys | Recovery UI can be operated |
| Android 11 FBE decryption | Owner credential opens `/data` and `/sdcard` |
| Keymaster 4.0 / Gatekeeper 1.0 | Shared key, DE/0, CE/0 and owner credential verified |
| WLAN service chain | IPA, qca, `wlan0`, and supplicant start correctly |
| WLAN connectivity | Scan, SAE join, DHCP, and internet probe succeed |
| Files, terminal, and fixed-partition mounts | Normal read operations work |
| App caches + system caches | Both selected together completed; a locked dual-app user does not block them |
| Data filesystem repair | Completed on device; the device-mapper cleanup error no longer appears |
| Small-partition backup and restore | Backup and restore completed for one smaller partition |
| Settings persistence | Theme, brightness, vibration and related settings survived a Recovery reboot |
| WLAN settings persistence | WLAN power, saved networks and credentials survived a Recovery reboot |
| USB drive read | The drive mounted and could be read |
| AW8697 haptics | Click and screen-off tick probes play successfully |
| MIUI update check | Latest version, package size, and mirrors returned |
| Fixed `recovery` image flash | fastboot write, read-back, and boot verified |
| EDL | In-system button fails; `fastboot oem edl` from bootloader enters 9008 |

## Implemented, awaiting full acceptance

| Feature | Status |
| --- | --- |
| Flash `boot` / `dtbo` / `vbmeta` from Install | Selection and write-back verification implemented; no real flash yet |
| SELinux relabel | Fixed-partition rules implemented; not run on the device |
| Script ZIP / `adb sideload` | Non-A/B script path implemented; end-to-end install pending |
| MIUI full-package download and install | Check path exists; final 2.7G install not accepted |
| Locked dual-app user's app data | Clearable through encrypted directory names; unit tests pass, device run pending |
| MTP file transfer | USB service exists; computer-side transfer not accepted |
| fastbootd | Implemented; fastbootd ↔ Recovery round trip pending |
| Reboot to bootloader / fastbootd | Pages exist; per-target UI acceptance pending |

## Partial support

| Feature | Limitation |
| --- | --- |
| Full backup and restore | One small partition is verified; full data, every system partition, and IMEI/EFS are not yet accepted together |
| USB drive | Read verified; write and abrupt-removal handling pending |
| MIUI full update package | Version checks work; A/B `payload.bin` is not applicable, only a fixed-partition script package may work |
| Skyward online self-update | Current update flow assumes A/B recovery partitions; not exposed for crux |
| Reflash Skyward after system update | Also designed around per-slot recovery partitions; not enabled for crux |
| EDL | In-system `reboot edl` is downgraded to a normal reboot; use bootloader plus `fastboot oem edl` |
| `init_boot` / `vendor_boot` images | crux has no `init_boot`; other targets are offered only when the partition exists |

## Unsupported / not applicable

| Feature | Reason |
| --- | --- |
| Dual boot | Current design requires A/B `boot`, `init_boot`, and a recovery partition per slot |
| A/B slot switching | crux has no slots |
| Virtual A/B snapshot merge | crux has no virtual A/B metadata or `super` |
| A/B `payload.bin` OTA | Device is non-A/B |
| Per-slot Skyward online update | crux has one recovery partition |
| Automatic Skyward restore after system updates | Same per-slot requirement |

## Publication boundaries

- Never commit full partition dumps, `persist`, `keymaster`, `keystore`, IMEI,
  or device serial numbers.
- Never commit WLAN passwords, private keys, signing keystores, or logs with
  personal data.
- Do not commit complete vendor firmware, proprietary binaries, or unredacted
  device handoff notes.
- Binary releases must link to the complete source at the corresponding Git tag
  and remain compatible with `GPL-3.0-or-later`.
