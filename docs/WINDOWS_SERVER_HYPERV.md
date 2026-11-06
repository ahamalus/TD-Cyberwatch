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
