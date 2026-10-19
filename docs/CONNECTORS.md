# Hosting connector setup and verification

CyberWatch connects to hosting accounts **read-only**. Each connection runs a test and capability
discovery; monitoring options are limited to capabilities shown as **Available**.

| Connector | Status | Credential | Capabilities verified at discovery |
|---|---|---|---|
| SFTP | Implemented, tested against a real SFTP server | Password or SSH private key (Ed25519/ECDSA/RSA) | listing, metadata, content read, hashing; log access only if configured paths are readable |
| cPanel UAPI | Implemented, tested against a mocked UAPI; **needs live verification** | cPanel API token | listing, metadata, content read/hashing |
| External HTTP/TLS | Implemented | none | availability, TLS (per website) |
| SSH commands, WHM, Plesk, DirectAdmin, provider security APIs, host agent, WordPress plugin | Planned (registered, cannot be selected) | — | — |

Never assumed for any connector: log access, server-side malware scanning, real-time file events,
provider security APIs.

## SFTP

1. Prefer a dedicated SSH key for CyberWatch, with read access to the website directories only. If your
   host supports it, use a chrooted/SFTP-only account.
2. In **Hosting Connections → Connect hosting**: hostname, port (22 or 2222 by default — others must be
   added to `CW_ALLOWED_SFTP_PORTS`), username, **authorised root directory** (e.g. `/home/acme/public_html`).
3. Save. The connection test: DNS → outbound policy → TCP → host key (recorded and pinned on first
   success) → authentication → SFTP subsystem → root listing. Capability discovery then lists the root,
   reads a single byte of one small file, and tests any configured log paths.
4. **Verify the host-key fingerprint** shown on the connection page against your provider for important
   accounts. If the server is rebuilt, use "trust new key" only after confirming with the provider.

Notes: symbolic links are recorded but never followed; hidden files (dotfiles) are inventoried; files above
the size limit are recorded as `skipped_size` and compared by size/time with low confidence.

## cPanel UAPI

1. In cPanel → *Security → Manage API Tokens*, create a token named "CyberWatch". Restrict by IP to the
   CyberWatch worker's egress IP if your cPanel version offers it. Set an expiry and rotate it regularly.
2. Connect with hostname (the server hostname with a valid certificate), port 2083, the cPanel username,
   root `public_html` (relative to the home directory), and the token.
3. Functions used: `Fileman::list_files` and `Fileman::get_file_content` only. Files larger than 5 MB are
   recorded as metadata-only.

### Live verification required before production use

The build environment could not reach the cPanel API documentation site, so the following were
implemented from secondary sources and must be confirmed against a live cPanel account:

- [ ] `list_files` honours `show_hidden=1` (dotfiles such as `.htaccess` appear). Discovery notes when no
      dotfiles are observed at the root.
- [ ] Per-entry fields `file`, `fullpath`, `type` (`file`/`dir`/`link`), `size`, `mtime`, `nicemode`.
- [ ] `get_file_content` with `from_charset=ISO-8859-1&to_charset=UTF-8` returns byte-exact content for
      binary files (compare a SHA-256 computed locally with the CyberWatch inventory hash).
- [ ] The `dir` parameter accepts home-relative paths such as `public_html/wp-content`.

Procedure: connect a test account, run a scan, then download 3 files (one text, one image, one `.htaccess`)
via cPanel File Manager and compare `sha256sum` with the inventory. Record results in BUILD_STATUS.md.

## When a capability is unavailable

| Message | Meaning | What to do |
|---|---|---|
| Credentials were rejected | Wrong password/key/token | Rotate the credential |
| Permission denied on root | Account cannot list that directory | Fix the root path or permissions |
| Server host key changed | Possible rebuild or interception | Confirm with provider, then re-trust |
| Destination not permitted | Private/internal address or disallowed port | Use the public hostname/allowed port |
| File content reading unavailable | Listing works but files cannot be read | Grant read permission; scans fall back to metadata-only (low confidence) |
| Log access untested | No log path configured | Configure absolute log paths if your host exposes them |

## Testing whether a provider supports SSH/SFTP or cPanel API

- SFTP: `sftp -P 22 user@host` from an admin machine; `ls` the web root.
- cPanel API: `curl -H "Authorization: cpanel USER:TOKEN" "https://HOST:2083/execute/Fileman/list_files?dir=public_html"`.
- If neither is offered (some shared hosts disable SSH and API tokens), only availability/TLS monitoring is
  possible; a future host agent or WordPress plugin connector would be required for file integrity.
