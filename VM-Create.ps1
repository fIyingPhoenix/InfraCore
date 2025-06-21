# Script parameters for installation and uninstallation
param (
    [switch]$Install,
    [switch]$Uninstall
)

# --- Configuration Variables ---

# Paths
$VMRootPath = "C:\Hyper-V"          # Root directory for Hyper-V files for this project
$VMPath = Join-Path -Path $VMRootPath -ChildPath "VMs"        # Storage for VM configuration files
$VHDPath = Join-Path -Path $VMRootPath -ChildPath "VHDs"       # Storage for Virtual Hard Disks

# ISO Paths - IMPORTANT: Update these paths to your ISO files
$ISO_UbuntuServer = "D:\ISOs\ubuntu.iso"       # Path to your Ubuntu Server ISO
$ISO_WindowsClient = "D:\ISOs\Win11.iso"       # Path to your Windows Client ISO

# Network Configuration
$DefaultWANSwitchName = "" # Will be selected by the user
$PrivateSwitchBaseName = "PrivateSwitch" # Base name for private switches (e.g., PrivateSwitch 1)

# --- VM Definitions ---
# Define each VM with its specific configuration.
# VHDSize, StartupMem, MinMem, MaxMem are in Bytes (e.g., 1GB, 512MB).
# SecureBootTemplate can be "MicrosoftUEFICertificateAuthority" or "MicrosoftWindows"
$vmDefinitions = @(
    # Routers
    @{ VMName = "Linux - Router 1";       ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 32GB; StartupMem = 1GB; MinMem = 512MB; MaxMem = 2GB; CPUCount = 1; IsWindows = $false },
    @{ VMName = "Linux - Router 2";       ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 32GB; StartupMem = 1GB; MinMem = 512MB; MaxMem = 2GB; CPUCount = 1; IsWindows = $false },

    # AD/DNS Servers
    @{ VMName = "Linux - AD_DNS 1";       ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 64GB; StartupMem = 2GB; MinMem = 1GB; MaxMem = 4GB; CPUCount = 2; IsWindows = $false },
    @{ VMName = "Linux - AD_DNS 2";       ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 64GB; StartupMem = 2GB; MinMem = 1GB; MaxMem = 4GB; CPUCount = 2; IsWindows = $false },

    # DHCP Server
    @{ VMName = "Linux - DHCP Server";    ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 32GB; StartupMem = 1GB; MinMem = 512MB; MaxMem = 2GB; CPUCount = 1; IsWindows = $false },

    # Mail Server
    @{ VMName = "Linux - Mail Server";    ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 64GB; StartupMem = 2GB; MinMem = 1GB; MaxMem = 4GB; CPUCount = 2; IsWindows = $false },

    # Nextcloud Server
    @{ VMName = "Linux - Nextcloud Server"; ISOPath = $ISO_UbuntuServer;  EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftUEFICertificateAuthority"; VHDSize = 128GB;StartupMem = 2GB; MinMem = 1GB; MaxMem = 4GB; CPUCount = 2; IsWindows = $false },

    # Windows Clients
    @{ VMName = "Windows - Client 1";     ISOPath = $ISO_WindowsClient; EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftWindows"; VHDSize = 64GB; StartupMem = 4GB; MinMem = 2GB; MaxMem = 8GB; CPUCount = 2; IsWindows = $true },
    @{ VMName = "Windows - Client 2";     ISOPath = $ISO_WindowsClient; EnableSecureBoot = $true; SecureBootTemplate = "MicrosoftWindows"; VHDSize = 64GB; StartupMem = 4GB; MinMem = 2GB; MaxMem = 8GB; CPUCount = 2; IsWindows = $true }  
)

# --- Script Logic ---

# Display help if no parameters provided
if (-not ($Install -or $Uninstall)) {
    Write-Host "VM Management Script - Usage:" -ForegroundColor Cyan
    Write-Host "  -Install                : Create VMs and private switches as defined in the script." -ForegroundColor Yellow
    Write-Host "  -Uninstall              : Remove all VMs and resources created by this script." -ForegroundColor Yellow
    exit
}

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Warning "This script requires Administrator privileges. Restarting as administrator..."
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Install) { $arguments += " -Install" }
    if ($Uninstall) { $arguments += " -Uninstall" }
    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
    exit
}

# Check if Hyper-V PowerShell module is available
if (-not (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)) {
    Write-Error "Hyper-V PowerShell module not found! Please ensure Hyper-V is installed and the module is available."
    exit
}

# --- Installation Logic ---
if ($Install) {
    Write-Host "`n--- Starting Installation Process ---" -ForegroundColor Green

    # Function to select the WAN virtual switch for initial VM connection
    function Select-WANVirtualSwitch {
        $switches = Get-VMSwitch
        if (-not $switches) {
            Write-Error "No virtual switches found. Please create an External or Internal virtual switch for WAN access first."
            exit
        }

        Write-Host "`nAvailable Virtual Switches (for initial WAN connection):" -ForegroundColor Cyan
        for ($i = 0; $i -lt $switches.Count; $i++) {
            Write-Host "  [$i] $($switches[$i].Name) (Type: $($switches[$i].SwitchType))"
        }

        $selection = Read-Host "`nEnter the number of the virtual switch to use for initial VM WAN access. Default: 0"
        $index = 0
        if (-not [string]::IsNullOrEmpty($selection) -and $selection -match "^\d+$") {
            $selectedIndex = [int]$selection
            if ($selectedIndex -ge 0 -and $selectedIndex -lt $switches.Count) {
                $index = $selectedIndex
            } else {
                Write-Warning "Invalid selection. Using the first available switch."
            }
        } elseif (-not [string]::IsNullOrEmpty($selection)) {
            Write-Warning "Invalid input. Using the first available switch."
        }
        
        Write-Host "[+] VMs will be initially connected to WAN switch: $($switches[$index].Name)" -ForegroundColor Cyan
        Write-Host "[!] Note: Internal network connections to PrivateSwitches need to be configured manually as per the README." -ForegroundColor Yellow
        return $switches[$index].Name
    }

    $DefaultWANSwitchName = Select-WANVirtualSwitch

    # Create storage directories
    foreach ($path in @($VMPath, $VHDPath)) {
        if (-not (Test-Path -Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Host "[+] Created directory: $path" -ForegroundColor Green
        }
    }

    # Create Private Switches as per documentation
    Write-Host "`n[+] Creating Private Switches..." -ForegroundColor Cyan
    for ($s = 1; $s -le 3; $s++) {
        $privSwitchName = "$PrivateSwitchBaseName $s"
        if (-not (Get-VMSwitch -Name $privSwitchName -ErrorAction SilentlyContinue)) {
            New-VMSwitch -Name $privSwitchName -SwitchType Private -Notes "Private network for InfraCore lab" | Out-Null
            Write-Host "  [+] Created Private Switch: $privSwitchName" -ForegroundColor Green
        } else {
            Write-Host "  [!] Private Switch '$privSwitchName' already exists. Skipping." -ForegroundColor Yellow
        }
    }

    # Create VMs
    Write-Host "`n[+] Creating Virtual Machines..." -ForegroundColor Cyan
    foreach ($vmDef in $vmDefinitions) {
        $VMName = $vmDef.VMName
        $VMStoragePath = Join-Path -Path $VMPath -ChildPath $VMName
        $VHDFile = Join-Path -Path $VHDPath -ChildPath "$VMName.vhdx"

        Write-Host "`n  --- Processing VM: $VMName ---" -ForegroundColor Blue

        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
            Write-Host "  [!] VM '$VMName' already exists. Skipping." -ForegroundColor Yellow
            continue
        }

        # Create VM folder
        if (-not (Test-Path -Path $VMStoragePath)) {
            New-Item -ItemType Directory -Path $VMStoragePath -Force | Out-Null
        }

        # Create Virtual Hard Disk
        if (-not (Test-Path -Path $VHDFile)) {
            Write-Host "  [+] Creating VHD: $VHDFile (Size: $([math]::Round($vmDef.VHDSize/1GB,0))GB)"
            New-VHD -Path $VHDFile -SizeBytes $vmDef.VHDSize -Dynamic | Out-Null
        }

        # Create Generation 2 VM
        Write-Host "  [+] Creating VM (CPU: $($vmDef.CPUCount), Startup RAM: $([math]::Round($vmDef.StartupMem/1MB,0))MB)"
        New-VM -Name $VMName -Generation 2 -MemoryStartupBytes $vmDef.StartupMem -VHDPath $VHDFile -Path $VMStoragePath -SwitchName $DefaultWANSwitchName | Out-Null
        
        # Configure Dynamic Memory
        Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes $vmDef.MinMem -MaximumBytes $vmDef.MaxMem
        
        # Set CPU cores
        Set-VMProcessor -VMName $VMName -Count $vmDef.CPUCount | Out-Null
        
        # Attach ISO
        if (Test-Path -Path $vmDef.ISOPath) {
            Write-Host "  [+] Attaching ISO: $($vmDef.ISOPath)"
            Add-VMDvdDrive -VMName $VMName -Path $vmDef.ISOPath | Out-Null
        } else {
            Write-Warning "  [!] ISO file not found: $($vmDef.ISOPath). VM will be created without an ISO."
        }
       
        # Configure Firmware (Secure Boot, TPM)
        if ($vmDef.EnableSecureBoot) {
            Write-Host "  [+] Enabling Secure Boot for $VMName."
            Set-VMFirmware -VMName $VMName -EnableSecureBoot On | Out-Null
            
            if (-not [string]::IsNullOrEmpty($vmDef.SecureBootTemplate)) {
                Write-Host "  [+] Applying Secure Boot Template: $($vmDef.SecureBootTemplate)"
                try {
                    Set-VMFirmware -VMName $VMName -SecureBootTemplate $vmDef.SecureBootTemplate -ErrorAction Stop | Out-Null
                } catch {
                    Write-Warning "  [!] Failed to apply Secure Boot Template '$($vmDef.SecureBootTemplate)' for $VMName. Error: $($_.Exception.Message)"
                    Write-Warning "  [!] VM might not boot correctly if the OS requires this specific template. Ensure the template name is valid."
                }
            }
        } else {
            Write-Host "  [+] Disabling Secure Boot for $VMName."
            Set-VMFirmware -VMName $VMName -EnableSecureBoot Off | Out-Null
        }

        # Enable TPM for Windows VMs (mandatory for Win11, good for others too)
        # This is done regardless of Secure Boot state for Windows, as TPM is a separate requirement/feature.
        if ($vmDef.IsWindows) {
            Write-Host "  [+] Enabling TPM for Windows VM: $VMName."
            try {
                Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector -ErrorAction Stop | Out-Null
                Enable-VMTPM -VMName $VMName -ErrorAction Stop | Out-Null
            } catch {
                Write-Warning "  [!] Failed to enable TPM for $VMName. Error: $($_.Exception.Message)"
                Write-Warning "  [!] Windows 11 installation might fail without TPM."
            }
        }

        # Set Boot Order to DVD first
        $DvdDrive = Get-VMDvdDrive -VMName $VMName | Select-Object -First 1
        if ($DvdDrive) {
            Write-Host "  [+] Setting DVD drive as first boot device."
            try {
                Set-VMFirmware -VMName $VMName -FirstBootDevice $DvdDrive -ErrorAction Stop
            } catch {
                Write-Warning "  [!] Could not set DVD as first boot device for $VMName. Error: $($_.Exception.Message)"
                Write-Warning "  [!] Manual check of boot order might be needed in Hyper-V Manager."
            }
        } else {
            Write-Warning "  [!] No DVD drive found to set boot order for $VMName (possibly no ISO attached)."
        }
        
        Write-Host "  [OK] Finished creating VM: $VMName" -ForegroundColor Green
    }
    Write-Host "`n--- Installation Process Completed ---" -ForegroundColor Green
}

# --- Uninstallation Logic ---
if ($Uninstall) {
    Write-Host "`n--- Starting Uninstallation Process ---" -ForegroundColor DarkYellow
    
    # Confirm removal of all resources
    $confirmUninstall = Read-Host "ARE YOU SURE you want to remove all VMs, VHDs, and Private Switches created by this script? (Y/N)"
    if ($confirmUninstall -ne "Y" -and $confirmUninstall -ne "y") {
        Write-Host "[!] Uninstall canceled by user." -ForegroundColor Yellow
        exit
    }

    # Remove VMs
    Write-Host "`n[-] Removing Virtual Machines and their VHDs..." -ForegroundColor Red
    foreach ($vmDef in $vmDefinitions) {
        $VMName = $vmDef.VMName
        $VMToDelete = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        
        if ($VMToDelete) {
            Write-Host "  --- Processing VM for deletion: $VMName ---" -ForegroundColor Magenta
            
            # Stop VM if running
            if ($VMToDelete.State -ne 'Off') {
                Write-Host "  [-] Stopping VM: $VMName"
                Stop-VM -VM $VMToDelete -Force -TurnOff -Confirm:$false
            }
            
            # Get VM hard disks before removing the VM
            $vmHardDisks = Get-VMHardDiskDrive -VMName $VMName | Select-Object -ExpandProperty Path
            
            Write-Host "  [-] Removing VM: $VMName"
            Remove-VM -VM $VMToDelete -Force -Confirm:$false
            
            # Remove associated VHD files
            if ($null -ne $vmHardDisks) {
                foreach ($diskPath in $vmHardDisks) {
                    if (Test-Path -Path $diskPath) {
                        Write-Host "  [-] Removing VHD: $diskPath"
                        Remove-Item -Path $diskPath -Force -Confirm:$false
                    }
                }
            }
            
            # Remove VM configuration folder
            $VMStoragePath = Join-Path -Path $VMPath -ChildPath $VMName
            if (Test-Path -Path $VMStoragePath) {
                Write-Host "  [-] Removing VM configuration folder: $VMStoragePath"
                Remove-Item -Path $VMStoragePath -Recurse -Force -Confirm:$false
            }
        } else {
            Write-Host "  [!] VM '$VMName' not found for deletion. Skipping." -ForegroundColor Yellow
        }
    }

    # Remove Private Switches
    Write-Host "`n[-] Removing Private Switches..." -ForegroundColor Red
    for ($s = 1; $s -le 3; $s++) {
        $privSwitchName = "$PrivateSwitchBaseName $s"
        $switchToRemove = Get-VMSwitch -Name $privSwitchName -ErrorAction SilentlyContinue
        if ($switchToRemove) {
            Write-Host "  [-] Removing Private Switch: $privSwitchName"
            Remove-VMSwitch -VMSwitch $switchToRemove -Force -Confirm:$false
        } else {
            Write-Host "  [!] Private Switch '$privSwitchName' not found. Skipping." -ForegroundColor Yellow
        }
    }
    
    # Ask to remove main VM and VHD directories if they are empty
    Write-Host "" # Newline for better readability
    $cleanupDirsConfirm = Read-Host "Do you want to attempt to remove the main VHD and VM directories ($VHDPath, $VMPath)? (Y/N)"
    if ($cleanupDirsConfirm -eq "Y" -or $cleanupDirsConfirm -eq "y") {
        foreach ($dirToRemove in @($VHDPath, $VMPath)) {
            if (Test-Path -Path $dirToRemove) {
                # Check if directory is empty
                if ((Get-ChildItem -Path $dirToRemove -ErrorAction SilentlyContinue).Count -eq 0) {
                    Write-Host "[-] Removing empty directory: $dirToRemove"
                    Remove-Item -Path $dirToRemove -Force -Confirm:$false
                } else {
                    Write-Warning "[!] Directory '$dirToRemove' is not empty. Manual cleanup might be required."
                }
            }
        }
        # Attempt to remove root project directory if empty
        if (Test-Path -Path $VMRootPath -PathType Container) {
             if ((Get-ChildItem -Path $VMRootPath -ErrorAction SilentlyContinue).Count -eq 0) {
                Write-Host "[-] Removing empty root project directory: $VMRootPath"
                Remove-Item -Path $VMRootPath -Force -Confirm:$false
            } else {
                Write-Warning "[!] Root project directory '$VMRootPath' is not empty. Manual cleanup might be required if all project items were expected to be removed."
            }
        }
    }
    
    Write-Host "`n--- Uninstallation Process Completed ---" -ForegroundColor Green
}

Write-Host "`nScript finished."