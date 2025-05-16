# Project InfraCore
#  Linux Active Directory Lab with DNS, DHCP, Mail, and Nextcloud

This project is a fully functional Linux-based lab environment that simulates a small enterprise network with multiple subnets, Active Directory (Samba), DNS routing, DHCP, a mail server, and Nextcloud integration.

---

  <p align="center">
    <a href="#Overview">Overview</a>
    <a href="#VMSetup">VM Setup</a>
    <a href="https://github.com/fIyingPhoenix/TrionControlPanel/issues">Request Feature</a>
  </p>



<h1 align="center"><b>Overview</b> </h1> 

<div id="Overview"></div>

### Network Structure

| Network       | Description           | Subnet            | Router Interface IP |
|---------------|-----------------------|-------------------|---------------------|
| Private 1     | Building 1 Clients     | 192.168.10.0/24   | 192.168.10.254      |
| Private 2     | Interbuilding (Bridge) | 10.0.0.0/8        | 10.0.0.1, 10.0.0.2  |
| Private 3     | Building 2 Clients     | 192.168.20.0/24   | 192.168.20.254      |
| WAN           | Internet Access        | DHCP or Static    | Depends on Host     |

## Components

- **2 Router VMs** with IP forwarding and NAT
- **2 AD/DNS Server** (`samba` + `bind9`)
- **1 DHCP Server**
- **1 Mail Server**
- **1 Nextcloud Server**
- **2 Client VMs** (join AD, test services)
- 
## Technologies Used

- Ubuntu Server 24.04 LTS
- Samba (Active Directory domain controller)
- Bind9 (DNS)
- iptables (NAT/routing)
- Nextcloud (self-hosted cloud platform)
- Netplan (for IP management)

## System Requirements (HOST)

- Minimum: 4 CPU cores, 16 GB RAM per VM
- Virtualization software (VirtualBox, VMware, Hyper-V). 

<h1 align="center"><b>VM Setup</b> </h1> 

<div id="VMSetup"></div>
This guide explains how to configure a virtual machine (VM).
In this example, I'm using Windows 11 Pro with Hyper-V.

 If you're looking for a detailed, step-by-step tutorial on how to set up a VM manually, click here.

For now, I'm using a PowerShell script to automatically create all 9 VMs.


You can download the script directly to your user directory using PowerShell, or manually from the GitHub repository.

```powershell
# Download the script
Invoke-WebRequest -Uri "https://github.com/fIyingPhoenix/InfraCore/raw/main/VM-Create.ps1" -OutFile "$HOME/VM-Create.ps1"
```
After downloading the script, edit it with Notepad or your preferred text editor. You can use the command below:
``` bash
# Edit the file
Start-Process notepad.exe "$HOME/VM-Create.ps1"
```
ISO Path: Update the script with the correct path to your Operation System ISO file:  
- `$ISO_Client` for Clients (windows ISO)
- `$ISO_Server` for Servers (Ubuntu ISO) 

RAM & CPU Cores: Adjust the memory and number of CPU cores as needed.

- `$MemoryMinimumBytes` Minimum Alocated memory
- `$MemoryMaximumBytes` Maximum Alocated Memory
- `$MemoryStartupBytes` Memory every Wm Starts with

VHD & Stat Files: Update the scriot with the correct path to save the Virtual Disks and Runtime Files

- `$VMPath` VM Runtime State File
- `$VHDPath` VM Virtual Disks

Save the file and run the script!
```
#Run the script!
cd $HOME; .\VM-Create.ps1
```

![image](images/createVM-output.png)

> [!NOTE]
> Make sure the boot order is correct, and change the RAM to at least 4GB for Windows 11.
