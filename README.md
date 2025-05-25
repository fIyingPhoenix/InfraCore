# Project InfraCore

## Linux Active Directory Lab with DNS, DHCP, Mail, and Nextcloud

This project provides a fully functional Linux-based lab environment that simulates a small enterprise network with multiple subnets, Active Directory (Samba), DNS routing, DHCP, a mail server, and Nextcloud integration.

<p align="center">
  <a href="#overview">Overview</a> • 
  <a href="#Hyper-V">Hyper-V Setup</a> • 
  <a href="#Router">Router Setup</a> • 
  <a hreg="#AD-DNS"> AD/DNS Servers</a>
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

The domain I'm using is `smoke-break.lan`. It's an inside joke among my classmates.

<h4 id="network-structure">Network Structure</h4>

| Network       | Description              | Subnet            | Router Interface IP |
|---------------|--------------------------|-------------------|---------------------|
| Private 1     | Building 1 Clients       | 192.168.10.0/24   | 192.168.10.254      |
| Private 2     | Interbuilding (Bridge)   | 172.16.0.0/16     | 172.16.0.1, 172.16.0.2|
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

> [!CAUTION]
> Before installing any virtualization software, ensure that hardware virtualization is enabled in your system's BIOS/UEFI settings. This is typically found under CPU settings as "Virtualization Technology," "VT-x," "AMD-V," or similar.

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
cd $HOME; .\VM-Create.ps1 -Install
# To remove the VM's and 
cd $HOME; .\VM-Create.ps1 -Uninstall
```

![VM Creation Output](images/createVM-output.png)


> [!TIP]
> Make sure to check the boot order for each VM after creation. For Windows 11 VMs, increase the RAM to at least 4GB and use 2 Cores to meet minimum requirements.

## Initial VM Setup

Start the VMs and install the operating systems. If you need guidance, you can find it here:
- [Ubuntu Installation Guide]()
- [Windows Installation Guide]()

> [!CAUTION]
> the first two Router VMs and assign just one NIC with the WAN connection to each VM. The other VMs will be installed after we configure the routers, as we need an internet connection to install and update the operating systems.

<div align="center">
  <h2 id="Router">Router Setup</h2>
</div>

I assume you've installed Ubuntu Minimal and configured a static IP for the main router (you should always have a static IP if possible). This guide will help you set up two Ubuntu 24.04 LTS-based routers with three NICs each. We'll configure Router 1 as the main gateway and Router 2 as a sub-router connected via an internal network.

<p align="center">
  <a href="#Router1">Router 1</a> •
  <a href="#Router2">Router 2</a> 
</p>

<h2 id="Router1">Router 1 Configuration</h2>

### Prepare the System

```bash 
# Make sure you use your own domain!
sudo apt update && sudo apt upgrade -y && sudo reboot
sudo apt install nano netfilter-persistent iputils-ping iptables
sudo hostnamectl set-hostname router1.smoke-break.lan
```

### Adding Network Interfaces

I assume you have just one NIC on your router (the "WAN" connection). We need to add 2 more NICs to the VM. You can do that manually in Hyper-V or using the commands below:

```powershell
# If you changed the variables in the script or created the VMs manually, make sure you use those variables.
Add-VMNetworkAdapter -VMName "Linux - Router 1" -SwitchName "PrivateSwitch 1" # The Private network for Building 1
Add-VMNetworkAdapter -VMName "Linux - Router 1" -SwitchName "PrivateSwitch 2" # The private network for Interbuilding (Bridge)
```

### Verify Network Interfaces

You can check if Ubuntu detected the new NICs:

```bash 
ip a
```

If the NICs are detected, you should have 4 adapters: `lo`, `eth0`, `eth1`, `eth2` (your names may differ):

![Router1Adapters](/images/router/router1Adatpters.PNG)

- `lo` is the loopback adapter (localhost)
- `eth0` should be the WAN connection 
- `eth1` should be the PrivateSwitch 1 (Building 1)
- `eth2` should be the PrivateSwitch 2 (Interbuilding, Bridge)

### Configure Netplan

First, navigate to the netplan config directory and list the files:

```bash
cd /etc/netplan && ls 
```

![Router1NetConf](/images/router/router1NetplanConf.PNG)

In this example, the config file is `50-cloud-init.yaml`. Create a backup before editing:

```bash
sudo cp 50-cloud-init.yaml 50-cloud-init.bc
```

Edit the config file with a text editor of your choice:

```bash
sudo nano 50-cloud-init.yaml
```

Edit the configuration like the example below:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0: # WAN interface
      addresses:
        - 10.100.18.19/24 # Make sure you use your WAN IP
      nameservers:
        addresses: [1.1.1.1, 1.0.0.1] # You can use different Public DNS servers; I prefer CloudFlare
      routes:
        - to: default
          via: 10.100.18.254 # Route to the WAN connection (default gateway of your WAN connection)
    eth1: # Building 1 clients
      addresses:
        - 192.168.10.254/24 
    eth2: # Bridge to Router 2
      addresses:
        - 172.16.0.1/16
      routes:
        - to: 192.168.20.0/24 
          via: 172.16.0.2 # Route to the Private 3 (Building 2)
```

Test the configuration:

```bash
sudo netplan try
```

Apply the settings:

```bash
sudo netplan apply
```

> [!TIP]
> If you encounter an error, open the config file and make sure you have the correct spacing and syntax.

### Enable IP Forwarding

```bash 
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ipforward.conf
sudo sysctl -p /etc/sysctl.d/99-ipforward.conf
```

### Set Up Network Address Translation (NAT)

```bash
# Make sure you are using the NIC that's connected to the WAN, in this example it's eth0
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Make Settings Persistent

```bash
sudo netfilter-persistent save
```

<h2 id="Router2">Router 2 Configuration</h2>

### Prepare the System

> [!TIP]
> Repeat the same system preparation steps as for Router 1, but change the hostname to `router2.smoke-break.lan`:

```bash 
# Make sure you use your own domain!
sudo apt update && sudo apt upgrade -y && sudo reboot
sudo apt install nano netfilter-persistent iputils-ping iptables
sudo hostnamectl set-hostname router2.smoke-break.lan
```

Now you can set up Router 2. Make sure you change the NIC to PrivateSwitch 2 (Interbuilding) and add a new NIC to it. You can do this manually in Hyper-V or use these commands:

```powershell
# Make sure to run the commands in order
Connect-VMNetworkAdapter -VMName "Linux - Router 2" -SwitchName "PrivateSwitch 2"
Add-VMNetworkAdapter -VMName "Linux - Router 2" -SwitchName "PrivateSwitch 3" 
```

### Verify Network Interfaces

Check to see if the NICs are visible in your OS:

```bash 
ip a
``` 

### Configure Netplan for Router 2

Make a backup of your current netplan config file:

```bash
cd /etc/netplan && sudo cp 50-cloud-init.yaml 50-cloud-init.bc
```

Edit the configuration:

```bash
sudo nano 50-cloud-init.yaml
```

Use this configuration:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - 172.16.0.2/16
      routes:
        - to: default
          via: 172.16.0.1
        - to: 192.168.10.0/24
          via: 172.16.0.1
    eth1:
      addresses:
        - 192.168.20.1/24
```

Test and apply the settings:

```bash
sudo netplan try
sudo netplan apply
```

### Enable Forwarding and Configure Firewall

```bash 
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ipforward.conf
sudo sysctl -p /etc/sysctl.d/99-ipforward.conf

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

### Make iptables Rules Persistent

```bash
sudo netfilter-persistent save
```

## Testing Your Configuration

Now you've configured both routers and can test connectivity using ping commands:

```bash
# Ping between routers
ping -c 3 172.16.0.1  # Ping the first router from the second one
ping -c 3 172.16.0.2  # Ping the second router from the first one

# Ping the private networks
ping -c 3 192.168.10.254
ping -c 3 192.168.20.254

# Test WAN connectivity
ping -c 3 1. 1.1.1
```

If all pings are successful, you've configured the routers correctly and you're ready to go. If you encounter any errors, review the steps to identify where you went wrong. Make sure the NICs are correctly configured and the config files have proper syntax.


<div align="center">
  <h2 id="Router">AD/DNS Servers Setup</h2>
</div>

Setting up Active Directory-like functionality on Linux typically involves Samba in AD DC (Domain Controller) mode, and BIND9 for DNS. We will use the servers named `Linux - Server 1` and `Linux - Server 3` for this setup.

## Initial Setup

Change the hostnames from `Linux - Server 1` to `PrivateNetwork 1` and from `Linux - Server 3` to `PrivateNetwork 3` so that they will be in their own private network. Start the VMs and install the OS.

When you get to the network configuration point, edit the entry to point to `Router 1` for `Server 1` and to `Router 2` for `Server 3`.

![EditIPV4Install](/images/ubuntu-Install/UbuntuEditIPV4Install.PNG)

**Server 1 Network Configuration:**
```plaintext
Subnet: 192.168.10.0/24
IP Address: 192.168.10.101
Gateway: 192.168.10.254
DNS: 1.1.1.1, 1.0.0.1 
```

**Server 3 Network Configuration:** 
```plaintext
Subnet: 192.168.20.0/24
IP Address: 192.168.20.101
Gateway: 192.168.20.254
DNS: 1.1.1.1, 1.0.0.1 
```

![EditIPV4installAddress](images/ubuntu-Install/UbuntuEditIPV4Edit.png)

The DNS will be later changed to use `Linux - Server 1` and `Linux - Server 3` as the main DNS resolvers. After you setup the networking, you should have internet access. Finish your installation and let's start!

## 1. Prerequisites (on both servers)

```bash 
# Make sure you use your own domain!
sudo apt update && sudo apt upgrade -y && sudo reboot
sudo apt install nano ufw iputils-ping samba krb5-user krb5-config winbind libpam-winbind libnss-winbind bind9 bind9utils dnsutils -y
```

> [!TIP]
> During installation, leave Kerberos config empty if asked - we'll configure it manually.

## 2. Set up Primary Domain Controller (Server 1)

### Configure Hostname & Hosts File

```bash 
hostnamectl set-hostname dns1.smoke-break.lan
```

Edit `/etc/hosts`:

```bash 
sudo nano /etc/hosts
```

Add your server IPv4 and domain name like in the example below. Make sure to use your domain name!

```plaintext
127.0.0.1       localhost
127.0.1.1       localhost
192.168.10.101  dns1.smoke-break.lan dns1
```

### Configure Samba as AD DC with BIND9

Move the old Samba config file and create a backup so you can restore it if needed:

```bash
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
```

Provision Active Directory:

```bash 
sudo samba-tool domain provision --use-rfc2307 --interactive
```

Answer the prompts:
- **Realm:** SMOKE-BREAK.LAN
- **Domain:** SMOKEBREAK
- **Server Role:** dc
- **DNS backend:** BIND9_DLZ
- **Admin password:** choose securely

> [!TIP]
> This process can take some time, especially on low-resource VMs or slow disks.
> - On SSD and decent CPU: a few seconds to 1–2 minutes
> - On slow systems (HDD, Raspberry Pi, low RAM): 5–10+ minutes is possible

If it doesn't continue after 15-20+ minutes:

1. Press `Ctrl+C` to cancel it (if it's still alive)
2. Check for stuck processes:
   ```bash 
   ps aux | grep samba 
   ```
3. If you see stuck Samba processes, kill them:
   ```bash 
   sudo pkill -f samba
   ```
4. Delete the old config and try again:
   ```bash
   sudo samba-tool domain provision --use-rfc2307 --interactive -d 5
   # The -d 5 flag gives more debug info
   ```

To check the logs:
```bash 
less /var/log/samba/log.samba
```

### Configure Kerberos

Edit `/etc/krb5.conf`:

```bash
sudo nano /etc/krb5.conf
```

```ini 
[libdefaults]
    default_realm = SMOKE-BREAK.LAN
    dns_lookup_realm = false
    dns_lookup_kdc = false
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    rdns = false
    fcc-mit-ticketflags = true

[realms]
    SMOKE-BREAK.LAN = {
        kdc = dns1.smoke-break.lan
        admin_server = dns1.smoke-break.lan
    }

[domain_realm]
    .smoke-break.lan = SMOKE-BREAK.LAN
    smoke-break.lan = SMOKE-BREAK.LAN
```

### Configure BIND9 for Samba

Add to `/etc/bind/named.conf` config file:

```bash
sudo nano /etc/bind/named.conf
```

Add this line:
```
include "/var/lib/samba/bind-dns/named.conf";
```

Adjust AppArmor:

```bash
sudo ln -s /var/lib/samba/bind-dns /etc/bind/
```

Restart services:

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

sudo reboot
```

Test DNS functionality:

```bash
host -t SRV _ldap._tcp.smoke-break.lan
host -t SRV _kerberos._udp.smoke-break.lan
host -t A dns1.smoke-break.lan
```
 
You should get an output like:

```
_ldap._tcp.smoke-break.lan has SRV record 0 100 389 dns1.smoke-break.lan.
_kerberos._udp.smoke-break.lan has SRV record 0 100 88 dns1.smoke-break.lan.
dns1.smoke-break.lan has address 192.168.10.101
```

### Configure the Firewall

```bash
sudo ufw allow 53
sudo ufw allow 88
sudo ufw allow 135
sudo ufw allow 389
sudo ufw allow 445
sudo ufw allow 464
sudo ufw allow 636
sudo ufw enable
```

## 3. Set up Secondary Domain Controller (Server 3)

### Configure Hostname & Hosts File

```bash 
sudo hostnamectl set-hostname dns2.smoke-break.lan
sudo nano /etc/hosts
```

```plaintext
127.0.0.1       localhost
127.0.1.1       dns2.smoke-break.lan dns2
192.168.20.101  dns2.smoke-break.lan dns2
```

### Join the Domain

Move the old Samba config file and create a backup:

```bash
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
```

Join the domain as a domain controller:

```bash
sudo samba-tool domain join SMOKE-BREAK.LAN DC --dns-backend=BIND9_DLZ --username=administrator
```

### Configure BIND9

Add to `/etc/bind/named.conf` config file:

```bash
sudo nano /etc/bind/named.conf
```

Add this line:
```
include "/var/lib/samba/bind-dns/named.conf";
```

Adjust AppArmor:

```bash
sudo ln -s /var/lib/samba/bind-dns /etc/bind/
```

### Restart Services

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

sudo reboot
```

### Test Secondary DC

Test with:

```bash
host -t SRV _ldap._tcp.smoke-break.lan
host -t A dns2.smoke-break.lan
```

### Configure Firewall

```bash
sudo ufw allow 53
sudo ufw allow 88
sudo ufw allow 135
sudo ufw allow 389
sudo ufw allow 445
sudo ufw allow 464
sudo ufw allow 636
sudo ufw enable
```

## 4. Client Configuration

Install the Windows clients now:
- `Win - Client 1` should be on `PrivateSwitch 1` (pointing to Server 1)
- `Win - Client 2` should be on `PrivateSwitch 2` (pointing to Server 3)


Configure the Windows clients to use the respective domain controllers as their DNS servers:

Client 1
- **Address:** 192.168.10.50
- **Netmask:** 255.255.255.0
- **Gateway:** 192.168.10.254
- **Primary DNS**  192.168.10.101
- **Secondary DNS:**  192.168.20.101

Client 2
- **Address:** 192.168.20.50
- **Netmask:** 255.255.255.0
- **Gateway:** 192.168.20.254
- **Primary DNS**  192.168.10.101
- **Secondary DNS:**  192.168.20.101

## Troubleshooting

If you encounter issues:

1. **Check service status:**
   ```bash
   sudo systemctl status samba-ad-dc
   sudo systemctl status bind9
   ```

2. **Check logs:**
   ```bash
   sudo tail -f /var/log/samba/log.samba
   sudo tail -f /var/log/bind/bind.log
   ```

3. **Test connectivity:**
   ```bash
   ping dns1.smoke-break.lan
   ping dns2.smoke-break.lan
   ```

4. **Verify domain functionality:**
   ```bash
   samba-tool domain info smoke-break.lan
   ```