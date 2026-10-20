# Simulate a website compromise on the LOCAL sample site so you can watch CyberWatch detect it.
# The "web shell" written here is inert text that merely looks suspicious; nothing is executed.
#
#   powershell -ExecutionPolicy Bypass -File .\simulate-attack.ps1         plant a fake web shell, deface, delete a page
#   powershell -ExecutionPolicy Bypass -File .\simulate-attack.ps1 reset   restore the sample site
param([ValidateSet("attack", "reset")][string]$Action = "attack")

$ErrorActionPreference = "Stop"
$Local = Join-Path $PSScriptRoot "deploy\local"
$Site = Join-Path $Local "sample-site\public_html"
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

if ($Action -eq "reset") {
    # Restore in place: the folder itself is mounted into the running containers.
    Get-ChildItem -Force $Site | Remove-Item -Recurse -Force
    Copy-Item -Recurse -Force (Join-Path $Local "sample-site-original\public_html\*") $Site
    Write-Host "Sample site restored. Run a scan to see CyberWatch return to normal."
    exit 0
}

$shell = "<?php`n/* CyberWatch local test file: harmless text that resembles a web shell. Not executable code. */`n// eval(base64_decode(`$_POST['cmd']));  <- typical attacker pattern, commented out`n"
[System.IO.File]::WriteAllText((Join-Path $Site "wp-content\uploads\wso-shell.php"), $shell, $Utf8NoBom)
[System.IO.File]::AppendAllText((Join-Path $Site "index.html"), "`n<!-- hacked by test-crew: simulated defacement for CyberWatch testing -->`n", $Utf8NoBom)
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Site "about.html")

Write-Host "Simulated attack applied to deploy\local\sample-site\public_html:"
Write-Host "  + added    wp-content\uploads\wso-shell.php   (script in an upload directory, web-shell name)"
Write-Host "  ~ modified index.html                         (defacement)"
Write-Host "  - deleted  about.html"
Write-Host ""
Write-Host "Now open the website in CyberWatch and click 'Run scan' (or wait for the schedule)."
