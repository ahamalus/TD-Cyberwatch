# Copies the encrypted CyberWatch backups from the CyberWatch VM to this Windows host every morning,
# checks their SHA-256 checksums and keeps 60 days. The files stay encrypted; this host never holds the key.
#
# One-time setup, in PowerShell opened with "Run as administrator" (asks for the VM password once):
#   powershell -ExecutionPolicy Bypass -File .\Pull-CyberWatchBackups.ps1 -Install
# Afterwards a scheduled task runs it daily at 06:30. Run it by hand any time without -Install.
param(
    [switch]$Install,
    [string]$VmHost = "192.168.1.242",
    [string]$User = "tdadmin",
    [string]$Dest = "C:\CyberWatch-Backups",
    [int]$KeepDays = 60
)
$ErrorActionPreference = "Continue"   # ssh/scp write progress to stderr; failures are checked explicitly
$Base = "C:\ProgramData\CyberWatch"
$Key = Join-Path $Base "backup_pull_key"
$Known = Join-Path $Base "known_hosts"
$Log = Join-Path $Base "backup-pull.log"
$Remote = "/var/backups/cyberwatch"
$SshOpts = @("-i", $Key, "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=$Known", "-o", "StrictHostKeyChecking=accept-new")

function Log($msg) {
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Write-Host $line
    Add-Content -Path $Log -Value $line
}

New-Item -ItemType Directory -Force -Path $Base, $Dest | Out-Null

if ($Install) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Write-Host "Run PowerShell as administrator for -Install." -ForegroundColor Red; exit 1 }
    # Only SYSTEM and administrators may read the pull key (OpenSSH refuses keys others can read).
    icacls $Base /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    if (-not (Test-Path $Key)) {
        ssh-keygen -q -t ed25519 -N '""' -C "cyberwatch-backup-pull" -f $Key
    }
    Write-Host "Authorising this host on $User@$VmHost (enter the VM password once)..."
    $pub = (Get-Content "$Key.pub" -Raw).Trim()
    # 'restrict' disables shells with terminals, port forwarding and agent forwarding for this key.
    "restrict $pub" | ssh -o UserKnownHostsFile=$Known -o StrictHostKeyChecking=accept-new "$User@$VmHost" `
        "umask 077; mkdir -p ~/.ssh; grep -qF '$pub' ~/.ssh/authorized_keys 2>/dev/null || cat >> ~/.ssh/authorized_keys"
    if ($LASTEXITCODE -ne 0) { Write-Host "Could not install the key on the VM." -ForegroundColor Red; exit 1 }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -VmHost $VmHost -User $User -Dest `"$Dest`" -KeepDays $KeepDays"
    $trigger = New-ScheduledTaskTrigger -Daily -At 6:30am
    Register-ScheduledTask -TaskName "CyberWatch backup copy" -Action $action -Trigger $trigger -User "SYSTEM" `
        -RunLevel Highest -Description "Copies encrypted CyberWatch backups from the VM and checks them." -Force | Out-Null
    Write-Host "Scheduled task 'CyberWatch backup copy' created (daily 06:30). Running a first copy now..."
}

$list = ssh @SshOpts "$User@$VmHost" "ls -1 $Remote" 2>$null
if ($LASTEXITCODE -ne 0) { Log "ERROR: cannot list $Remote on $VmHost (is the VM running? is the key installed?)"; exit 1 }
$copied = 0
foreach ($name in $list) {
    if (-not $name -or $name -like "*.part") { continue }
    $target = Join-Path $Dest $name
    if (Test-Path $target) { continue }
    scp @SshOpts -q "${User}@${VmHost}:$Remote/$name" $target 2>$null
    if ($LASTEXITCODE -ne 0) { Log "ERROR: copy failed for $name"; Remove-Item $target -ErrorAction SilentlyContinue; continue }
    $copied++
}

# Verify every set against its SHA256SUMS file.
$bad = 0
foreach ($sums in Get-ChildItem $Dest -Filter "SHA256SUMS-*") {
    foreach ($line in Get-Content $sums.FullName) {
        $hash, $file = $line -split '\s+\*?', 2
        $path = Join-Path $Dest $file
        if (-not (Test-Path $path)) { Log "ERROR: $file listed in $($sums.Name) is missing"; $bad++; continue }
        if ((Get-FileHash $path -Algorithm SHA256).Hash.ToLower() -ne $hash.ToLower()) { Log "ERROR: checksum mismatch for $file"; $bad++ }
    }
}

# Audit anchors (a few bytes each) are kept indefinitely: they prove the audit trail was not rewritten later.
Get-ChildItem $Dest -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) -and $_.Name -notlike "audit-anchor-*" } | Remove-Item -Force
$sets = (Get-ChildItem $Dest -Filter "SHA256SUMS-*").Count
$newest = Get-ChildItem $Dest -Filter "SHA256SUMS-*" | Sort-Object Name -Descending | Select-Object -First 1
Log ("copied {0} new file(s); {1} backup set(s) held; newest {2}; checksum problems: {3}" -f $copied, $sets, $newest.Name, $bad)
if ($bad -gt 0) { exit 1 }
