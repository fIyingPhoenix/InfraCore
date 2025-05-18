# Project InfraCore

## Linux Active Directory Lab with DNS, DHCP, Mail, and Nextcloud

This project provides a fully functional Linux-based lab environment that simulates a small enterprise network with multiple subnets, Active Directory (Samba), DNS routing, DHCP, a mail server, and Nextcloud integration.

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#Hyper-V">Hyper-V Setup</a> 
</p>

---

<div align="center">
  <h2 id="overview">Overview</h2>
</div>

<p align="center">
  <a href="#network-structure">Network Structure</a> •
  <a href="#components">Components</a> •
  <a href="#technologies-used">Technologies Used</a> •
  <a href="#system-requirements">System Requirements</a> 
</p>
Project InfraCore provides a comprehensive lab environment for learning and testing enterprise network configurations. The setup includes multiple interconnected subnets, domain controllers, and various network services to simulate a real-world corporate environment.

<h4 id="network-structure">Network Structure</h4>

| Network       | Description              | Subnet            | Router Interface IP |
|---------------|--------------------------|-------------------|---------------------|
| Private 1     | Building 1 Clients       | 192.168.10.0/24   | 192.168.10.254      |
| Private 2     | Interbuilding (Bridge)   | 10.0.0.0/8        | 10.0.0.1, 10.0.0.2  |
| Private 3     | Building 2 Clients       | 192.168.20.0/24   | 192.168.20.254      |
| WAN           | Internet Access          | DHCP or Static    | Depends on Host     |

<h4 id="components">Components</h4>

- **2 Router VMs** with IP forwarding and NAT
- **2 AD/DNS Servers** (`samba` + `bind9`)
- **1 DHCP Server**
- **1 Mail Server**
- **1 Nextcloud Server**
- **2 Client VMs** (join AD, test services)

<h4 id="technologies-used">Technologies Used</h4>

- Ubuntu Server 24.04 LTS
- Samba (Active Directory domain controller)
- Bind9 (DNS)
- iptables (NAT/routing)
- Nextcloud (self-hosted cloud platform)
- Netplan (for IP management)

<h4 id="system-requirements">System Requirements (HOST)</h4>

- **Minimum**: 4 CPU cores, 16 GB RAM
- **Recommended**: 8+ CPU cores, 32+ GB RAM
- **Storage**: At least 250 GB free space
- **Virtualization software**: VirtualBox, VMware, or Hyper-V
- **Hardware virtualization**: Virtualization must be enabled in BIOS/UEFI settings (Intel VT-x/AMD-V)

> **Important**: Before installing any virtualization software, ensure that hardware virtualization is enabled in your system's BIOS/UEFI settings. This is typically found under CPU settings as "Virtualization Technology," "VT-x," "AMD-V," or similar.

---

<div align="center">
  <h2 id="Hyper-V">Hyper-V Setup</h2>
</div>

This guide explains how to configure the virtual machines for the lab environment. In this example, we're using Windows 11 Pro with Hyper-V.

### Enable Hyper-V (Windows Host only)

Before creating VMs, you need to enable Hyper-V on your Windows system:

## Using PowerShell (Administrator)**

Run this command in PowerShell with administrator privileges:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

If you're looking for a detailed, step-by-step tutorial on how to set up a VM manually, [click here](Hyper-VSetup.md).

For faster deployment, you can use our PowerShell script to automatically create all 9 VMs.

### Automated VM Creation

You can download the script directly to your user directory using PowerShell, or manually from the GitHub repository:

```powershell
# Download the script
Invoke-WebRequest -Uri "https://github.com/fIyingPhoenix/InfraCore/raw/main/VM-Create.ps1" -OutFile "$HOME/VM-Create.ps1"
```

### Configure the Script

After downloading the script, edit it with Notepad or your preferred text editor:

```powershell
# Edit the file
Start-Process notepad.exe "$HOME/VM-Create.ps1"
```

#### Required Modifications:

1. **ISO Paths**: Update with the correct paths to your ISO files:
   - `$ISO_Client` - Path to client OS ISO (Windows)
   - `$ISO_Server` - Path to server OS ISO (Ubuntu)

2. **Memory Allocation**:
   - `$MemoryMinimumBytes` - Minimum allocated memory
   - `$MemoryMaximumBytes` - Maximum allocated memory
   - `$MemoryStartupBytes` - Initial memory at VM startup

3. **Storage Locations**:
   - `$VMPath` - Location for VM runtime state files
   - `$VHDPath` - Location for virtual hard disks

### Run the Script

Once configured, run the script to create all VMs:

```powershell
# Run the script
cd $HOME; .\VM-Create.ps1
```

![VM Creation Output](images/createVM-output.png)

> **Note**: Make sure to check the boot order for each VM after creation. For Windows 11 VMs, increase the RAM to at least 4GB and 2 Cores to meet minimum requirements.

Start the VM's and install the Operations system. if you need  a guid you cand find it here:
[Ubuntu]()
[windows]()