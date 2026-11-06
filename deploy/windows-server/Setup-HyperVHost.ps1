# Prepares a Windows Server (2019/2022/2025) Hyper-V host to run several Linux VMs behind ONE public IP.
#
# Network.Mode = "NAT" (default): the VMs get a private network on this host.
#   1. Creates a private Hyper-V switch and a Windows NAT network (10.10.0.0/24 by default).
#   2. Forwards public ports 80/443 to the "edge" VM (Caddy), plus any extra ports (e.g. Jitsi UDP 10000).
#   3. Opens those ports in Windows Firewall.
# Network.Mode = "LAN": the VMs join an existing external switch with their own office-LAN addresses;
#   the office router forwards 80/443 to the edge VM (the script prints exactly what to set).
# Both modes then create the VMs listed in the config (fixed memory, CPU weights, auto-start, Ubuntu ISO attached).
#
# Run in an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1 -PlanOnly   # show what would happen
#   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1             # apply
#
# Safe to run again: existing switches, NAT rules and VMs are reused, never deleted.
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "hyperv-config.psd1"),
    [switch]$PlanOnly,
    [switch]$SkipVmCreation
)

$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Note($msg) { Write-Host "    $msg" }

function ConvertTo-UInt32([string]$ip) {
    $b = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($b)
    return [BitConverter]::ToUInt32($b, 0)
}
function Test-InPrefix([string]$ip, [string]$prefix) {
    $net, $len = $prefix.Split("/")
    $mask = if ([int]$len -eq 0) { [uint32]0 } else { [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - [int]$len)) }
    return ((ConvertTo-UInt32 $ip) -band $mask) -eq ((ConvertTo-UInt32 $net) -band $mask)
}

# ---------------------------------------------------------------- load and validate the plan
if (-not (Test-Path $ConfigPath)) { Fail "Configuration not found: $ConfigPath" }
$cfg = Import-PowerShellDataFile -Path $ConfigPath
$net = $cfg.Network
$lanMode = $net.Mode -eq "LAN"
# Default gateway the VMs use: the office router (LAN) or this host's address on the private network (NAT).
$gateway = if ($lanMode) { $net.Gateway } else { $net.HostGateway }
$vms = @($cfg.VMs)
$edge = $vms | Where-Object { $_.Name -eq $cfg.EdgeVm }
if (-not $edge) { Fail "EdgeVm '$($cfg.EdgeVm)' is not in the VMs list." }

$names = $vms | ForEach-Object { $_.Name }
$ips = $vms | ForEach-Object { $_.IP }
if (($names | Select-Object -Unique).Count -ne $names.Count) { Fail "VM names must be unique." }
if (($ips | Select-Object -Unique).Count -ne $ips.Count) { Fail "VM IP addresses must be unique." }
foreach ($vm in $vms) {
    if (-not (Test-InPrefix $vm.IP $net.Prefix)) { Fail "VM '$($vm.Name)' IP $($vm.IP) is outside $($net.Prefix)." }
    if ($vm.IP -eq $gateway) { Fail "VM '$($vm.Name)' uses the gateway address $gateway." }
}
$forwards = @(
    @{ Protocol = "TCP"; Port = 80; ToVm = $edge.Name; Why = "HTTP (certificates + redirect to HTTPS)" }
    @{ Protocol = "TCP"; Port = 443; ToVm = $edge.Name; Why = "HTTPS for every subdomain" }
    @{ Protocol = "UDP"; Port = 443; ToVm = $edge.Name; Why = "HTTP/3" }
) + @($cfg.ExtraPortForwards | Where-Object { $_ })
foreach ($f in $forwards) {
    if (-not ($vms | Where-Object { $_.Name -eq $f.ToVm })) { Fail "Port forward $($f.Protocol) $($f.Port) points to unknown VM '$($f.ToVm)'." }
}

$hostRamGB = 0; $hostCores = 0
try {
    $hostRamGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $hostCores = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
} catch { Note "Could not read host hardware; skipping the capacity check." }
$vmRamGB = ($vms | Measure-Object -Property MemoryGB -Sum).Sum
$vmCpu = ($vms | Measure-Object -Property vCPU -Sum).Sum

Step "Plan"
$vms | ForEach-Object {
    [pscustomobject]@{ VM = $_.Name; IP = $_.IP; vCPU = $_.vCPU; "RAM GB" = $_.MemoryGB; "Disk GB" = $_.DiskGB; Purpose = $_.Purpose }
} | Format-Table -AutoSize | Out-String -Width 220 | Write-Host
Note "Host: $hostRamGB GB RAM, $hostCores logical processors. VMs: $vmRamGB GB RAM, $vmCpu vCPU."
$forwards | ForEach-Object {
    $to = ($vms | Where-Object Name -eq $_.ToVm).IP
    $via = if ($lanMode) { "Router must forward" } else { "Public" }
    Note ("{5} {0} {1} -> {2} ({3}:{1})  {4}" -f $_.Protocol, $_.Port, $_.ToVm, $to, $_.Why, $via)
}
if ($hostRamGB -gt 0 -and $vmRamGB -gt ($hostRamGB - 6)) {
    Fail "The VMs need $vmRamGB GB but the host has $hostRamGB GB; keep at least 6 GB for Windows. Reduce MemoryGB."
}
if ($cfg.UbuntuIso -like "*[*?]*") {
    # A wildcard picks the newest matching ISO, e.g. C:\ISO\ubuntu-24.04*-live-server-amd64.iso
    $iso = Get-ChildItem -Path $cfg.UbuntuIso -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    $cfg.UbuntuIso = if ($iso) { $iso.FullName } else { $cfg.UbuntuIso }
}
Note "Ubuntu installer: $($cfg.UbuntuIso)$(if (-not (Test-Path $cfg.UbuntuIso)) { '  (NOT FOUND yet)' })"
if ($PlanOnly) { Note "Plan only: nothing was changed."; exit 0 }

# ---------------------------------------------------------------- prerequisites
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Run this script in PowerShell opened with 'Run as administrator'."
}
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    Fail "Hyper-V is not installed. Run:  Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart   then run this script again."
}

if ($lanMode) {
    Step "Existing switch '$($net.SwitchName)'"
    if (-not (Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue)) {
        Fail "Switch '$($net.SwitchName)' not found. Check the name with: Get-VMSwitch"
    }
    Note "Found. The VMs join the office network directly; no NAT or Windows port forwarding is used."
    Step "Checking that the VM addresses are free on the network"
    foreach ($vm in $vms) {
        if (-not (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) -and (Test-Connection $vm.IP -Count 1 -Quiet)) {
            Fail "$($vm.IP) (for '$($vm.Name)') already answers on the network. Choose a free address in the config."
        }
    }
    Note "Addresses are free."
} else {
    Step "Checking that nothing on Windows already uses the forwarded ports"
    $busy = foreach ($f in $forwards) {
        if ($f.Protocol -eq "TCP") {
            Get-NetTCPConnection -LocalPort $f.Port -State Listen -ErrorAction SilentlyContinue
        } else {
            Get-NetUDPEndpoint -LocalPort $f.Port -ErrorAction SilentlyContinue
        }
    }
    if ($busy) {
        $busy | Select-Object LocalAddress, LocalPort, OwningProcess,
            @{ n = "Program"; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } |
            Format-Table -AutoSize | Out-String -Width 220 | Write-Host
        Fail ("These ports are in use on Windows (often IIS, 'System' = http.sys). Move that site to another port, " +
              "e.g. 8081, and add it to the edge Caddyfile as http://$($net.HostGateway):8081, then run again.")
    }
    Note "Ports are free."

    # ---------------------------------------------------------------- private switch, host address, NAT
    Step "Private switch '$($net.SwitchName)'"
    if (-not (Get-VMSwitch -Name $net.SwitchName -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $net.SwitchName -SwitchType Internal | Out-Null
        Note "Created."
    } else { Note "Already exists." }

    $ifAlias = "vEthernet ($($net.SwitchName))"
    if (-not (Get-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $net.HostGateway -ErrorAction SilentlyContinue)) {
        New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $net.HostGateway -PrefixLength $net.PrefixLength | Out-Null
        Note "Host address $($net.HostGateway) assigned."
    }

    Step "NAT network '$($net.NatName)' ($($net.Prefix))"
    $existingNat = @(Get-NetNat -ErrorAction SilentlyContinue)
    $nat = $existingNat | Where-Object { $_.Name -eq $net.NatName }
    if (-not $nat) {
        $other = $existingNat | Where-Object { $_.InternalIPInterfaceAddressPrefix -ne $net.Prefix }
        if ($other) {
            Fail ("Windows allows one NAT network per host and '$($other[0].Name)' ($($other[0].InternalIPInterfaceAddressPrefix)) already exists " +
                  "(often created by Docker Desktop or WSL). Set Network.Prefix to that range, or remove it with Remove-NetNat if unused.")
        }
        $nat = $existingNat | Where-Object { $_.InternalIPInterfaceAddressPrefix -eq $net.Prefix }
        if (-not $nat) {
            New-NetNat -Name $net.NatName -InternalIPInterfaceAddressPrefix $net.Prefix | Out-Null
            Note "Created."
        }
    }
    $natName = if ($nat) { @($nat)[0].Name } else { $net.NatName }

    Step "Port forwarding from the public IP"
    foreach ($f in $forwards) {
        $to = ($vms | Where-Object Name -eq $f.ToVm).IP
        $current = Get-NetNatStaticMapping -NatName $natName -ErrorAction SilentlyContinue |
            Where-Object { $_.Protocol -eq $f.Protocol -and $_.ExternalPort -eq $f.Port }
        if ($current -and $current.InternalIPAddress -eq $to -and $current.InternalPort -eq $f.Port) {
            Note "$($f.Protocol) $($f.Port) -> $to already set."
            continue
        }
        if ($current) { $current | Remove-NetNatStaticMapping -Confirm:$false }
        Add-NetNatStaticMapping -NatName $natName -Protocol $f.Protocol -ExternalIPAddress "0.0.0.0" -ExternalPort $f.Port `
            -InternalIPAddress $to -InternalPort $f.Port | Out-Null
        Note "$($f.Protocol) $($f.Port) -> $($f.ToVm) ($to)."
    }

    Step "Windows Firewall"
    foreach ($f in $forwards) {
        $ruleName = "HyperV-Apps $($f.Protocol) $($f.Port) to $($f.ToVm)"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Group "HyperV-Apps" -Direction Inbound -Action Allow `
                -Protocol $f.Protocol -LocalPort $f.Port | Out-Null
            Note "Allowed inbound $($f.Protocol) $($f.Port)."
        }
    }
}

# ---------------------------------------------------------------- virtual machines
if ($SkipVmCreation) { Note "Skipping VM creation (-SkipVmCreation)." }
else {
    Step "Virtual machines"
    if (-not (Test-Path $cfg.UbuntuIso)) {
        Fail "Ubuntu ISO not found at $($cfg.UbuntuIso). Download Ubuntu Server 24.04 LTS and update UbuntuIso in the config."
    }
    New-Item -ItemType Directory -Force -Path $cfg.VmFolder | Out-Null
    $delay = 0
    foreach ($vm in $vms) {
        if (Get-VM -Name $vm.Name -ErrorAction SilentlyContinue) {
            Note "$($vm.Name): already exists, left unchanged."
            continue
        }
        $vhd = Join-Path $cfg.VmFolder "$($vm.Name)\$($vm.Name).vhdx"
        New-VM -Name $vm.Name -Generation 2 -MemoryStartupBytes ([int64]$vm.MemoryGB * 1GB) -SwitchName $net.SwitchName `
            -NewVHDPath $vhd -NewVHDSizeBytes ([int64]$vm.DiskGB * 1GB) -Path $cfg.VmFolder | Out-Null
        Set-VMMemory -VMName $vm.Name -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $vm.Name -Count $vm.vCPU -RelativeWeight $vm.CpuWeight
        # Ubuntu boots with Secure Boot using the Microsoft UEFI CA template.
        Set-VMFirmware -VMName $vm.Name -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
        $dvd = Add-VMDvdDrive -VMName $vm.Name -Path $cfg.UbuntuIso -Passthru
        Set-VMFirmware -VMName $vm.Name -FirstBootDevice $dvd
        # Start automatically with the host, edge first, others staggered; shut down cleanly with it.
        Set-VM -Name $vm.Name -AutomaticStartAction Start -AutomaticStartDelay $delay -AutomaticStopAction ShutDown `
            -Notes $vm.Purpose
        $delay += 30
        Note "$($vm.Name): created ($($vm.vCPU) vCPU, $($vm.MemoryGB) GB, $($vm.DiskGB) GB disk)."
    }
}

Step "Done. Next steps"
Note "1. Start each VM in Hyper-V Manager (Connect -> Start) and install Ubuntu Server 24.04."
Note "   On the network screen choose 'Edit IPv4' -> Manual and enter:"
foreach ($vm in $vms) {
    Note ("     {0,-12} subnet {1}  address {2}  gateway {3}  DNS {4}" -f $vm.Name, $net.Prefix, $vm.IP, $gateway, $net.DnsServers)
}
Note "   Tick 'Install OpenSSH server'. After installing, remove the ISO: Settings -> DVD Drive -> None."
Note "2. Point every subdomain's DNS A record at this server's public IP."
Note "3. On the edge VM, run deploy/windows-server/edge/install-edge.sh (see docs/WINDOWS_SERVER_HYPERV.md)."
if ($lanMode) {
    Note "4. LAST, once the edge serves every site: in the office router, forward to $($edge.IP):"
    $forwards | Where-Object { $_.ToVm -eq $edge.Name } | ForEach-Object { Note "     $($_.Protocol) $($_.Port)" }
    $forwards | Where-Object { $_.ToVm -ne $edge.Name } | ForEach-Object {
        Note "   and $($_.Protocol) $($_.Port) to $(($vms | Where-Object Name -eq $_.ToVm).IP) ($($_.Why))"
    }
}
