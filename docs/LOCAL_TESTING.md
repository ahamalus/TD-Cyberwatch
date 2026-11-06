# Testing CyberWatch on your own computer

This kit runs the complete platform on your computer with Docker. It includes:

- the database
- the background workers
- the three portals
- a **sample website** to monitor
- a **mail catcher**

You can watch CyberWatch detect a simulated hack without touching any real website or hosting account. Nothing is
sent to the internet. Every email lands in a local inbox.

> Local testing only. The kit switches off staff MFA, uses plain http and allows private network
> addresses. Never copy its `.env` to a server; use [DEPLOY_CYBERWATCH_TRUSTDATA_NG.md](DEPLOY_CYBERWATCH_TRUSTDATA_NG.md) for that.

## 1. What you need

| | |
|---|---|
| Computer | Windows 10/11, macOS or Linux with **8 GB RAM** (16 GB recommended) and 10 GB free disk |
| Docker | [Docker Desktop](https://www.docker.com/products/docker-desktop/), installed and **running**. On Windows, accept the WSL 2 option during installation. |
| Internet | Only for the first start, to download base images and libraries (about 1.5 GB) |

## 2. Download

**Option A, ZIP:**
1. Open https://github.com/ahamalus/TD-Cyberwatch.
2. Switch the branch selector to `claude/new-session-7dmc53`, or to `main` once pull request 1 is merged.
3. Click **Code → Download ZIP** and extract it, for example to `C:\CyberWatch` or `~/CyberWatch`.

**Option B, Git:**
```bash
git clone -b claude/new-session-7dmc53 https://github.com/ahamalus/TD-Cyberwatch.git CyberWatch
```

## 3. Start

**Windows:** open PowerShell in the extracted folder (Shift + right-click the folder → *Open PowerShell window here*):
```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1
```

**macOS / Linux:** open a terminal in the folder:
```bash
./start-local.sh
```

The script does the following:
1. Creates a `.env` file with fresh random passwords and keys.
2. Builds and starts all the containers. The first run takes 5–15 minutes; later starts take seconds.
3. Waits until the application is healthy.
4. Creates a demo organisation and a platform administrator.

It then prints the sign-in details and saves them to `local-credentials.txt`:

| What | Where |
|---|---|
| CyberWatch | http://localhost:8080 |
| Email inbox (Mailpit) | http://localhost:8025 |
| Platform admin | `admin@trustdata.ng`, password in `local-credentials.txt` |
| Demo customer (synthetic data) | `demo@demo.example.com` / `Demo-Only-Password-2026!` |

## 4. Walk-through: detect a simulated hack

1. **Create a customer account.**
   - Open http://localhost:8080 and click **Create account**. Use any email address; nothing is really sent.
   - The verification email appears in Mailpit (http://localhost:8025).
2. **Connect the sample hosting account.** Go to **Hosting Connections → Connect hosting** and fill in these values:

   | Field | Value |
   |---|---|
   | Connection type | SFTP |
   | Server hostname | `sftp.cyberwatch.test` |
   | Port | `2222` |
   | SFTP username | `sampleuser` |
   | Password | the *Sample hosting* password from `local-credentials.txt` |
   | Authorised root directory | `/public_html` |

   Click **Test connection**. CyberWatch records the server's host key and shows the following:
   - file listing, metadata, reading and hashing as **available**
   - malware scanning and real-time events as **unsupported**

   This is honest capability discovery: it reports what this server actually allows.
3. **Add the website.** Go to **Websites → Add website**, set the URL to `http://site.cyberwatch.test:8080/` and choose the
   connection from step 2.
4. **Turn on alert emails.**
   - Go to **Notifications → New policy**, choose channel **Email**, minimum severity *Medium*, and add yourself (or the *Owner* role) as recipient.
   - New organisations start with no alert policy, so incidents are recorded but nobody is emailed until you create one.
5. **Take the first scan.**
   - Open the website and click **Scan files**: about 6 files are inventoried with SHA-256 hashes, which form the baseline.
   - Click **Check availability**: the site shows **Up**.
6. **Simulate the attack.** In the same folder:
   - Windows: `powershell -ExecutionPolicy Bypass -File .\simulate-attack.ps1`
   - macOS / Linux: `./simulate-attack.sh`

   The script makes three changes to the sample site:
   - plants an inert fake web shell in `wp-content/uploads/` (text only, it cannot run)
   - appends a "defacement" line to `index.html`
   - deletes `about.html`
7. **Scan again** by clicking **Scan files**. The results are:
   - The scan reports **3 changes**: 1 added, 1 modified and 1 deleted.
   - A **High** incident opens: *Suspicious file added: wp-content/uploads/wso-shell.php*. It has hashed evidence and a risk explanation.
   - The alert email arrives in Mailpit within about 30 seconds.
8. **Work the incident.** Acknowledge it, add notes and resolve it. You can also try **Reports** (CSV/PDF) and **Support**.
   Sign in as the platform admin to see Administration, and the dark Operations portal at http://localhost:8080/ops/overview.
9. **Undo the attack** with `simulate-attack.ps1 reset` or `./simulate-attack.sh reset`, then scan again.

The sample website's files live in `deploy/local/sample-site/public_html`. You can edit, add or delete files there yourself
and scan again to see how each kind of change is reported.

### Monitoring a real website from your computer
You can also add a real SFTP or cPanel account you are authorised to monitor. Monitoring is read-only: CyberWatch never
writes, deletes or quarantines files.

The local kit allows private network addresses. Use it only with accounts you control, and stop the kit when you are done.

## 5. Everyday commands

| Task | Windows | macOS / Linux |
|---|---|---|
| Start again after a reboot | `powershell -ExecutionPolicy Bypass -File .\start-local.ps1` | `./start-local.sh` |
| Stop (data kept) | `... .\start-local.ps1 stop` | `./start-local.sh stop` |
| Delete everything and start fresh | `... .\start-local.ps1 reset` | `./start-local.sh reset` |
| Container status | `docker compose ps` | same |
| Logs of a service | `docker compose logs -f api` (or `worker-monitoring`, `worker-notifications`, `web`) | same |

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop and wait until it shows *Engine running*. |
| Port 8080 or 8025 already in use | Edit `CW_WEB_PORT` / `CW_MAILPIT_PORT` in `.env`, then start again. |
| "did not become ready" | `docker compose ps`, then `docker compose logs migrate api`. Make sure Docker Desktop has at least 4 GB of memory (*Settings → Resources*). |
| Build fails while downloading | Check your internet connection or company proxy, then run the start script again. It resumes where it stopped. |
| Sign-in fails after deleting `.env` | The database still uses the old passwords. Run the `reset` command, then start again. |
| Scan finds no changes after the attack script | Make sure you ran the script in the same folder that you started CyberWatch from. |
