# Several apps on one Windows Server and one public IP (Hyper-V)

This guide runs CyberWatch and your other applications as separate Ubuntu virtual machines on one Windows
Server, all sharing a single public IP address.

```
Internet ── public IP ──► Windows NAT ──► edge VM (Caddy, HTTPS for every subdomain)
                              │                ├─► cyberwatch.trustdata.ng → 10.10.0.20:8080
                              │                ├─► meet.trustdata.ng       → 10.10.0.30:8000
                              │                └─► app3/app4 …             → 10.10.0.40 / .50
                              └── UDP 10000 ──► jitsi VM (media; not HTTP)
```

Every VM lives on a private network, `10.10.0.0/24`, which the internet cannot reach. Only ports 80/443 (to the edge
VM) and the extra ports you list are forwarded. Caddy on the edge VM obtains and renews a Let's Encrypt
certificate for each subdomain.

Files: `deploy/windows-server/`

| File | Runs on | Purpose |
|---|---|---|
| `hyperv-config.psd1` | — | Your layout: VM names, private IPs, CPU/RAM/disk, extra port forwards |
| `Setup-HyperVHost.ps1` | Windows host (admin PowerShell) | Creates the private switch, NAT, port forwards, firewall rules and the VMs |
| `edge/Caddyfile.example` | edge VM | Subdomain → VM routing |
| `edge/install-edge.sh` | edge VM | Installs Caddy, firewall, validates and applies the Caddyfile |

## 1. Windows host

1. Edit `hyperv-config.psd1`:
   - Set `VmFolder` (an SSD drive) and `UbuntuIso`. Download Ubuntu Server 24.04 LTS from https://ubuntu.com/download/server.
   - Keep or adjust the VM list.
2. Check the plan without changing anything:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1 -PlanOnly
   ```
3. Apply it. Run this in PowerShell opened with **Run as administrator**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1
   ```
   - If Hyper-V is missing, the script prints the command that installs it (a restart is needed).
   - If Windows itself already uses port 80 or 443 (usually IIS), the script stops and lists the program. Move those IIS sites to another
     port (e.g. 8081) and route them through the edge (`reverse_proxy 10.10.0.1:8081` in the Caddyfile).
4. Install Ubuntu in each VM: Hyper-V Manager → Connect → Start.
   - On the network screen choose **Edit IPv4 → Manual** and use the values the script prints: subnet `10.10.0.0/24`, the VM's address, gateway `10.10.0.1`, DNS `1.1.1.1,8.8.8.8`.
   - Tick **Install OpenSSH server**.
   - After installing, set the DVD drive to *None*.

You can reach the VMs over SSH from the Windows host: `ssh youruser@10.10.0.20`.

## 2. DNS

Create an **A record** for every subdomain pointing at the server's **public IP**. The script never changes DNS.

## 3. Edge VM (10.10.0.10)

```bash
git clone -b claude/new-session-7dmc53 https://github.com/ahamalus/TD-Cyberwatch.git
cd TD-Cyberwatch/deploy/windows-server/edge
nano Caddyfile.example        # your subdomains → VM addresses
sudo bash install-edge.sh
```

Re-run `sudo bash install-edge.sh` after every Caddyfile change. It validates the file before applying it.

## 4. CyberWatch VM (10.10.0.20)

```bash
curl -fsSL https://raw.githubusercontent.com/ahamalus/TD-Cyberwatch/claude/new-session-7dmc53/deploy/scripts/bootstrap-server.sh -o bootstrap.sh
sudo CW_DOMAIN=cyberwatch.trustdata.ng ACME_EMAIL=team@trustdata.ng EDGE_IP=10.10.0.10 \
     BRANCH=claude/new-session-7dmc53 bash bootstrap.sh
```

With `EDGE_IP` set, CyberWatch does not run its own HTTPS proxy:
- It serves on `10.10.0.20:8080`, accepting connections from the edge VM only. The edge provides HTTPS.
- It needs outbound access to customers' hosting (SFTP 22, cPanel 2083, HTTPS). The NAT provides this.

Then create the first administrator, as described in `DEPLOY_CYBERWATCH_TRUSTDATA_NG.md` step 3.

## 5. Jitsi and other apps

Jitsi needs **UDP 10000** forwarded straight to its VM. This is already in `ExtraPortForwards`. It must also
advertise the public IP: for docker-jitsi-meet, set `JVB_ADVERTISE_IPS=<public IP>` in its `.env`. Any other
non-HTTP port (mail, databases for remote clients, etc.) is added the same way in `ExtraPortForwards`.

## Capacity (64 GB / 16 cores)

The example layout gives the VMs 42 GB and 22 vCPU, leaving about 20 GB for Windows and headroom.
- **CPU:** a mild CPU overcommit is normal. Jitsi has a higher CPU weight, so video hearings stay smooth during CyberWatch scans.
- **Memory:** dynamic memory is off, so one VM cannot starve another.

## Health check and updates (CyberWatch VM)

Check every component (containers, workers, scheduler, job queue, audit trail, firewall, disk):
```bash
sudo bash /opt/cyberwatch/deploy/scripts/healthcheck.sh
```
Every line should read `PASS`. The script exits with an error if anything fails, so it can also run from cron.

Update to the latest version, then re-check:
```bash
cd /opt/cyberwatch && sudo -u cyberwatch git pull
sudo -u cyberwatch docker compose -f docker-compose.yml up -d --build
sudo bash deploy/scripts/healthcheck.sh
```

Customers paying by invoice or bank transfer: go to **Platform Administration → Customers → Activate plan** and record
the payment reference. The plan runs for the chosen term; record the next payment before it ends to extend it.

## Public access through Cloudflare Tunnel (no port forwarding)

Use this when the internet connection cannot forward ports reliably, or its public IP can change (e.g. Starlink).
`cloudflared` on the edge VM connects out to Cloudflare; Cloudflare serves `https://cyberwatch.trustdata.ng`.
The router and the other sites (Jitsi, APC, adsgcsc) are not touched.

```
Visitor -> Cloudflare (HTTPS) -> cloudflared (edge VM) -> Caddy 127.0.0.1:8088 -> CyberWatch 192.168.1.242:8080
```

Caddy passes CyberWatch the visitor IP from Cloudflare's `Cf-Connecting-Ip` header. It trusts that header
only on the local tunnel entrance, so visitors cannot forge their address for rate limits or the audit trail.

1. **Move the domain's DNS to Cloudflare.**
   - Create a free Cloudflare account and choose **Add a domain** → `trustdata.ng` → Free plan.
   - Compare the imported records with cPanel → Zone Editor. Check the MX, `mail`, SPF/DKIM/DMARC TXT records (`default._domainkey`), `www`, `webmail` and `cpanel` especially.
   - Set every imported record to **DNS only** (grey cloud) so the website and email keep working exactly as before.
   - At go54, turn **DNSSEC** off if it is on. Then replace the name servers `ns1/ns2.wghservers.com` with the two Cloudflare ones.
   - Wait for Cloudflare to report the domain as **Active**.
2. **Edge VM:** apply the config and install the tunnel:
   ```bash
   cd ~/TD-Cyberwatch && git pull && cd deploy/windows-server/edge
   sudo bash install-edge.sh Caddyfile.trustdata-r630
   ```
3. **Cloudflare dashboard → Zero Trust → Networks → Tunnels → Create a tunnel** (type *Cloudflared*), named e.g. `trustdata-edge`.
   Copy the token shown in the install command, then on the edge VM run:
   ```bash
   sudo bash install-cloudflared.sh
   ```
   Paste the token when asked; it is hidden and not stored in the shell history.
4. **Public hostname:** in the Cloudflare DNS settings, delete the `cyberwatch` A record first. Then add the tunnel's public hostname:
   - Subdomain `cyberwatch`
   - Domain `trustdata.ng`
   - Service **HTTP**, URL `127.0.0.1:8088`
5. **Check from a phone on mobile data:** open `https://cyberwatch.trustdata.ng`.

DNS changes for trustdata.ng are made in Cloudflare from now on. Edits in the cPanel Zone Editor no longer take effect.

