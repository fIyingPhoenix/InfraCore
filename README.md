# Project InfraCore
#  Linux Active Directory Lab with DNS, DHCP, Mail, and Nextcloud

This project is a fully functional Linux-based lab environment that simulates a small enterprise network with multiple subnets, Active Directory (Samba), DNS routing, DHCP, a mail server, and Nextcloud integration.

---

  <p align="center">
    <a href="#Overview">Overview</a>
    <a href="#VMSetup">VM Setup</a>
    <a href="https://github.com/fIyingPhoenix/TrionControlPanel/issues">Request Feature</a>
  </p>



# Overview 

<div id="Overview"></div>
### Network Structure

| Network       | Description           | Subnet            | Router Interface IP |
|---------------|-----------------------|-------------------|---------------------|
| Private 1     | Building 1 Clients     | 192.168.10.0/24   | 192.168.10.254      |
| Private 2     | Interbuilding (Bridge) | 10.0.0.0/8        | 10.0.0.1, 10.0.0.2            |
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

<div id="VMSetup"></div>
