# Data and Security Policy

## Sensitive data

Do not commit or attach any of the following to issues, discussions, pull
requests, releases, or the repository:

- full or partial partition dumps;
- `persist`, `frp`, `keymaster`, `keystore`, `modemst`, `fsg`, or similar
  device-identity partitions;
- IMEI, serial numbers, advertising IDs, Google account identifiers, or
  device-unlock data;
- WLAN passwords, credentials, tokens, private keys, or signing keystores;
- screenshots or logs containing personal files, account details, or unredacted
  device identifiers.

When a diagnostic report is necessary, extract only the relevant lines and
redact identifiers. `HANDOFF_*.md`, `.cargo-tmp/`, `$out/`, `dump_all/`,
`stock/`, generated images, and common firmware dumps are excluded by
`.gitignore`; this is a safety net, not permission to place sensitive data in
the worktree.

## Reporting a problem

For security-sensitive reports, use GitHub's private vulnerability reporting
feature when it is enabled for the repository. Do not publish credentials,
private keys, partition dumps, or personal account data in a public issue.

This fork is experimental and provides no security-response or update-time
guarantee. See [FORK_NOTICE.md](FORK_NOTICE.md).
