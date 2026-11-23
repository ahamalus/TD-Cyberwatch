# Hosting connector setup and verification

CyberWatch connects to hosting accounts **read-only**. Each connection runs a test and capability
discovery; monitoring options are limited to capabilities shown as **Available**.

| Connector | Status | Credential | Capabilities verified at discovery |
|---|---|---|---|
| SFTP | Implemented, tested against a real SFTP server | Password or SSH private key (Ed25519/ECDSA/RSA) | listing, metadata, content read, hashing; log access only if configured paths are readable |
| cPanel UAPI | Implemented; verified live on a CloudLinux/CageFS cPanel host (Nov 2026) | cPanel API token | listing, metadata, content read/hashing; log access (`~/access-logs`, daily archives in `~/logs`) |
| SSH (read-only commands) | Implemented, tested against an in-process SSH server | Password or SSH private key | everything SFTP verifies, plus server-side fingerprints (`sha256sum`/`md5sum`) when the host allows commands; log access defaults to `~/access-logs` and `~/logs` |
| External HTTP/TLS | Implemented | none | availability, TLS (per website) |
| WHM API | Implemented, tested against a simulated WHM; **not yet verified on a live server** | WHM API token (reseller or root) | same as cPanel UAPI, for the chosen account; account existence, ownership and suspension checked at every test |
| Plesk, DirectAdmin, provider security APIs, host agent, WordPress plugin | Planned (registered, cannot be selected) | — | — |

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

## SSH (read-only commands)

Use this instead of SFTP when the account also allows SSH commands (most cPanel hosts with *Shell Access*
enabled; CloudLinux "jailshell" is fine). It does everything the SFTP connector does over the same single
connection, with the same host-key pinning, and adds:

- **Server-side fingerprints.** CyberWatch may run exactly two programs: `sha256sum -- <files>` and
  `md5sum -- <files>`. Every argument is a path inside the authorised root, shell-quoted; nothing else is
  ever executed (enforced in code by an allow-list, and covered by tests that try `rm`, `sh`, `cat` and
  command injection in file names). Content that was already scanned is recognised by its fingerprint and
  not downloaded again, so the weekly full check costs a few commands instead of downloading the whole site,
  and a file altered with a forged modification time is still caught.
- **Cross-check.** Before trusting the server's fingerprints in a scan, one file is downloaded and hashed
  locally; any mismatch (or any command error) switches back to downloading every file, like SFTP. A host
  that can lie about fingerprints could equally serve altered files over SFTP, so this adds no new trust.
- **Live access logs** from `~/access-logs` (and the archives in `~/logs`) without configuring a path,
  because SSH sees the account the way the account owner does (cPanel's API cannot follow that link on
  CageFS hosts).

If the host refuses commands (SFTP-only or chrooted accounts), the connection still works: the hashing
capability says *"every file is downloaded instead"*.

## WHM API (reseller or server)

For hosts and resellers: one WHM token reaches every cPanel account it owns, so customers do not each have
to create a cPanel token. Add **one connection per cPanel account**; they share the WHM hostname, username
and token, and differ in *cPanel account to monitor*.

1. In WHM → *Development → Manage API Tokens*, create a token named "CyberWatch". **Prefer a reseller
   token** and give it only the ACLs these calls need (listing accounts and the account-functions privilege
   that permits `uapi_cpanel`). A root token works but can do far more than CyberWatch needs. Restrict it to
   the CyberWatch worker's IP if your WHM offers it; set an expiry and rotate it.
2. Connect with hostname (valid certificate), port 2087 (others must be added to `CW_ALLOWED_WHM_PORTS`),
   the WHM username, the cPanel account name, and the authorised root relative to that account's home
   (default `/public_html`).
3. The connection test calls `accountsummary` (the account exists, this WHM user owns it, and whether it is
   suspended), then lists the root as that account.

Only these functions are ever called, enforced by an allow-list in `connectors/whm.py` and covered by tests:
`accountsummary`, and `uapi_cpanel` with `Fileman::list_files` / `Fileman::get_file_content` (the same
read-only functions as the cPanel connector). Logs default to the account's `~/access-logs` and `~/logs`.

### Live verification checklist (not yet done)
- [ ] `uapi_cpanel` response nests the UAPI result in `data.uapi`, with `metadata.result` = 1 on success.
- [ ] A reseller token with minimal ACLs can call `accountsummary` and `uapi_cpanel` for its own accounts,
      and is refused for accounts it does not own.
- [ ] Byte-exact content through `uapi_cpanel` (compare `sha256sum` of 3 files, as for cPanel).
- [ ] Log access through `uapi_cpanel` on CageFS hosts (expect `~/logs` archives, as with cPanel).

## cPanel UAPI

1. In cPanel → *Security → Manage API Tokens*, create a token named "CyberWatch". Restrict by IP to the
   CyberWatch worker's egress IP if your cPanel version offers it. Set an expiry and rotate it regularly.
2. Connect with hostname (the server hostname with a valid certificate), port 2083, the cPanel username,
   root `public_html` (relative to the home directory), and the token.
3. Functions used: `Fileman::list_files` and `Fileman::get_file_content` only. Files larger than 5 MB are
   recorded as metadata-only.

4. **Access logs (optional, verified):**
   - **Where:** `~/access-logs`, cPanel's live *Raw Access* logs, and `~/logs`, the daily gzip archives.
     `~/access-logs` is a link to the server's domain-log folder; hosts that jail accounts (CloudLinux
     CageFS) make it unreachable through the API ("directory … does not exist"). There, enable *Archive
     logs in your home directory* so `~/logs` is filled after each daily statistics run.
   - **How they are read:** with the same two Fileman functions as website files.
   - **When analysis starts:** only after the connection test reads a log and recognises the format.
   - **If the logs are elsewhere:** set the folder under *Log directories* on the connection, home-relative
     like the root, for example `/access-logs`.
   - **Prerequisite:** *Metrics → Raw Access* must be enabled.
   - **To check on a live account:**
     - [ ] `list_files dir=access-logs` lists the domain logs (it is a symbolic link to the server's domain-log
       folder).
     - [ ] `get_file_content` returns the current log; note the size limit for large logs.
     - [ ] Whether "Delete each domain's access logs after statistics are processed" is enabled, because that
       decides how often analysis must run.

### Live verification

Verified in November 2026 against a production cPanel account on a CloudLinux/CageFS host (trustdata.ng):
listing including dotfiles, byte-exact content, home-relative paths, and log access through the daily
archives in `~/logs` (the live `~/access-logs` link is not readable through the API on CageFS). The
original checklist is kept below for other hosts:

- [x] `list_files` honours `show_hidden=1` (dotfiles such as `.htaccess` appear). Discovery notes when no
      dotfiles are observed at the root.
- [x] Per-entry fields `file`, `fullpath`, `type` (`file`/`dir`/`link`), `size`, `mtime`, `nicemode`.
- [x] `get_file_content` with `from_charset=ISO-8859-1&to_charset=UTF-8` returns byte-exact content for
      binary files (compare a SHA-256 computed locally with the CyberWatch inventory hash).
- [x] The `dir` parameter accepts home-relative paths such as `public_html/wp-content`.

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
