# Trust Data PowerEdge R630 (Windows Server 2025, 80 GB RAM, 24 cores), office network 192.168.1.0/24.
#
# The new VMs join the existing "External-LAN" switch with their own office addresses, like jitsi-meet.
# Nothing existing is changed by Setup-HyperVHost.ps1: IIS (adsgcsc :80, apc-campaign :8081) and the
# jitsi-meet VM keep running as they are. The edge VM later takes over ports 80/443 at the router and
# forwards each subdomain to the right place.
#
#   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1 -ConfigPath .\trustdata-r630.psd1 -PlanOnly
#   powershell -ExecutionPolicy Bypass -File .\Setup-HyperVHost.ps1 -ConfigPath .\trustdata-r630.psd1
@{
    Network = @{
        Mode       = "LAN"
        SwitchName = "External-LAN"
        Prefix     = "192.168.1.0/24"
        Gateway    = "192.168.1.1"          # office router
        DnsServers = "1.1.1.1,8.8.8.8"
    }

    VmFolder  = "C:\Hyper-V"                                    # C: has the free space (D: is full)
    UbuntuIso = "C:\ISO\ubuntu-24.04*-live-server-amd64.iso"   # newest 24.04 point release in C:\ISO

    EdgeVm = "edge"

    # Existing: jitsi-meet (192.168.1.240, 8 GB) is not listed here and is never touched.
    VMs = @(
        @{ Name = "edge";       IP = "192.168.1.241"; vCPU = 2; MemoryGB = 2; DiskGB = 20;  CpuWeight = 150; Purpose = "Caddy: HTTPS for every subdomain on 98.97.76.237" }
        @{ Name = "cyberwatch"; IP = "192.168.1.242"; vCPU = 4; MemoryGB = 8; DiskGB = 120; CpuWeight = 100; Purpose = "TrustData CyberWatch (cyberwatch.trustdata.ng)" }
    )

    # Jitsi's UDP 10000 is already forwarded by the router to 192.168.1.240; leave it as it is.
    ExtraPortForwards = @()
}
