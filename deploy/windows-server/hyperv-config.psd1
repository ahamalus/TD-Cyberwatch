# Hyper-V layout for one Windows Server with ONE public IP address.
# Edit this file, then run Setup-HyperVHost.ps1 (see docs/WINDOWS_SERVER_HYPERV.md).
#
# How traffic flows:
#   Internet -> public IP:80/443 -> Windows NAT -> "edge" VM (Caddy) -> the right VM by subdomain
# Every VM sits on a private network (10.10.0.0/24) that is not reachable from the internet,
# except for the ports listed under ExtraPortForwards.
#
# Sizing below fits a 64 GB / 16-core host: 42 GB to VMs, the rest for Windows and headroom.
@{
    Network = @{
        SwitchName   = "AppsInternal"     # private Hyper-V switch created by the script
        NatName      = "AppsNat"          # Windows allows only ONE NAT network per host
        Prefix       = "10.10.0.0/24"
        HostGateway  = "10.10.0.1"        # the Windows host's address on the private network
        PrefixLength = 24
        DnsServers   = "1.1.1.1,8.8.8.8"  # used inside the VMs (no DHCP on this network)
    }

    # Folder for the VM disks (use an SSD volume) and the Ubuntu Server installer ISO
    # (download ubuntu-24.04.x-live-server-amd64.iso from https://ubuntu.com/download/server).
    VmFolder  = "D:\Hyper-V"
    UbuntuIso = "D:\ISO\ubuntu-24.04.3-live-server-amd64.iso"

    # The edge VM receives ports 80 and 443 from the public IP.
    EdgeVm = "edge"

    # One entry per VM. MemoryGB is fixed (dynamic memory is switched off so no VM can starve another).
    # CpuWeight: 100 = normal; raise it for latency-sensitive workloads (e.g. video conferencing).
    VMs = @(
        @{ Name = "edge";       IP = "10.10.0.10"; vCPU = 2; MemoryGB = 2;  DiskGB = 20; CpuWeight = 150; Purpose = "Caddy reverse proxy + HTTPS for all subdomains" }
        @{ Name = "cyberwatch"; IP = "10.10.0.20"; vCPU = 4; MemoryGB = 8;  DiskGB = 80; CpuWeight = 100; Purpose = "TrustData CyberWatch (cyberwatch.trustdata.ng)" }
        @{ Name = "jitsi";      IP = "10.10.0.30"; vCPU = 8; MemoryGB = 16; DiskGB = 60; CpuWeight = 200; Purpose = "Jitsi Meet video hearings" }
        @{ Name = "app3";       IP = "10.10.0.40"; vCPU = 4; MemoryGB = 8;  DiskGB = 60; CpuWeight = 100; Purpose = "Your third application" }
        @{ Name = "app4";       IP = "10.10.0.50"; vCPU = 4; MemoryGB = 8;  DiskGB = 60; CpuWeight = 100; Purpose = "Your fourth application" }
    )

    # Non-web ports that must go straight to one VM (Caddy only handles HTTP/HTTPS).
    # Jitsi's media bridge needs UDP 10000. Remove entries you do not need.
    ExtraPortForwards = @(
        @{ Protocol = "UDP"; Port = 10000; ToVm = "jitsi"; Why = "Jitsi video/audio media" }
    )
}
