# Script parameters for installation and uninstallation
param (
    [switch]$Install,
    [switch]$Uninstall
)

# Common Configuration Variables
$VMRootPath = "C:\Hyper-V"  # Change this to your desired root path
$VMPath = "$VMRootPath\VMs" # Path for VM storage
$VHDPath = "$VMRootPath\VHDs" # Path for VHD storage
$MemoryMinimumBytes = 512MB # Minimum memory for dynamic memory
$MemoryMaximumBytes = 2GB   # Maximum memory for dynamic memory
$MemoryStartupBytes = 1GB   # Startup memory
$CPUCoreAllocate = 2        # Number of CPU cores to allocate
$VHDSizeBytes = 64GB        # Size of the VHD
$ServerBaseName = "Linux - Server" # Base name for server VMs
$ClientBaseName = "Win - Client"   # Base name for client VMs
$RouterBaseName = "Linux - Router" # Base name for router VMs
$SwitchBaseName = "PrivateSwitch"  # Base name for private switches 

# Ensure ISOs point to different files as needed
$ISO_Client = "d:\ISOs\client.iso"
$ISO_Server = "d:\ISOs\server.iso"

# Display help if no parameters provided
if (-not ($Install -or $Uninstall)) {
    Write-Host "VM Management Script - Usage:" -ForegroundColor Cyan
    Write-Host "  -Install                : Create VMs and private switches" -ForegroundColor Yellow
    Write-Host "  -Uninstall              : Remove all VMs and resources created by this script" -ForegroundColor Yellow
    exit
}

# Check for elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[X] Missing privileges! Restarting as administrator..." -ForegroundColor Yellow
    
    # Add parameters to restart command
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Install) { $arguments += " -Install" }
    if ($Uninstall) { $arguments += " -Uninstall" }
    
    Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs
    exit
}

# Check if Hyper-V is installed
if (-not (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)) {
    Write-Host "[X] Hyper-V PowerShell module not found! Please ensure Hyper-V is installed." -ForegroundColor Red
    exit
}
# MAIN VM CREATION SECTION (INSTALL) 
if ($Install) {
# Function to select a virtual switch 
function Select-VirtualSwitch {
    $switches = Get-VMSwitch
    
    if (-not $switches) {
        Write-Host "[X] No virtual switches found. Please create a virtual switch first." -ForegroundColor Red
        exit
    }
    
    # Show available switches
    Write-Host "`nAvailable Virtual Switches:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $switches.Count; $i++) {
        $switchType = $switches[$i].SwitchType
        Write-Host "[$i] $($switches[$i].Name) (Type: $switchType)" -ForegroundColor DarkYellow
    }
    
    # Prompt for switch selection
    $selection = Read-Host "`nEnter the number of the virtual switch to use (default: 0)"
    
    # Default to first switch if no input
    if ([string]::IsNullOrEmpty($selection)) {
        $selection = 0
    }
    
    # Validate selection
    try {
        $index = [int]$selection
        if ($index -lt 0 -or $index -ge $switches.Count) {
            Write-Host "[X] Invalid selection. Using the first available switch." -ForegroundColor Yellow
            $index = 0
        }
    }
    catch {
        Write-Host "[X] Invalid input. Using the first available switch." -ForegroundColor Yellow
        $index = 0
    }
    
    return $switches[$index].Name
}

# Select the virtual switch to use
$SwitchName = Select-VirtualSwitch
Write-Host "[+] Using virtual switch: $SwitchName" -ForegroundColor Cyan

# Create storage directories if they don't exist
if (-not (Test-Path -Path $VMPath)) {
    New-Item -ItemType Directory -Path $VMPath -Force | Out-Null
    Write-Host "[+] Created VM storage path: $VMPath" -ForegroundColor Green
}
if (-not (Test-Path -Path $VHDPath)) {
    New-Item -ItemType Directory -Path $VHDPath -Force | Out-Null
    Write-Host "[+] Created VHD storage path: $VHDPath" -ForegroundColor Green
}

# Define VM groups
$vmGroups = @(
    @{ BaseName = $RouterBaseName; Count = 2; ISO = $ISO_Server; EnableSecureBoot = $false },
    @{ BaseName = $ServerBaseName; Count = 5; ISO = $ISO_Server; EnableSecureBoot = $false },
    @{ BaseName = $ClientBaseName; Count = 2; ISO = $ISO_Client; EnableSecureBoot = $true }
)

# Create VMs
foreach ($group in $vmGroups) {
    $baseName = $group.BaseName
    $count = $group.Count
    $isoPath = $group.ISO
    $enableSecureBoot = $group.EnableSecureBoot
    
    for ($i = 1; $i -le $count; $i++) {
        $VMName = "$baseName $i"
        $VMStoragePath = Join-Path -Path $VMPath -ChildPath $VMName
        $VHDFile = Join-Path -Path $VHDPath -ChildPath "$VMName.vhdx"
        
        Write-Host "`n[+] Starting creation of VM: $VMName" -ForegroundColor Blue
        
        # Check if VM already exists
        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
            Write-Host "[!] VM '$VMName' already exists, skipping." -ForegroundColor Yellow
            continue
        }
        
        # Create VM folder
        if (-not (Test-Path -Path $VMStoragePath)) {
            New-Item -ItemType Directory -Path $VMStoragePath -Force | Out-Null
        }

        # Create Virtual HD first
        if (-not (Test-Path -Path $VHDFile)) {
            Write-Host "[+] Creating virtual hard disk: $VHDFile" -ForegroundColor Cyan
            New-VHD -Path $VHDFile -SizeBytes $VHDSizeBytes -Dynamic | Out-Null
        }
        
        # Create Generation 2 VM
        Write-Host "[+] Creating VM with $CPUCoreAllocate cores and $([math]::Round($MemoryStartupBytes/1GB, 1))GB RAM" -ForegroundColor Cyan
        New-VM -Name $VMName -Generation 2 -MemoryStartupBytes $MemoryStartupBytes -VHDPath $VHDFile -Path $VMStoragePath -SwitchName $SwitchName | Out-Null
        
        # Configure Dynamic Memory
        Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes $MemoryMinimumBytes -MaximumBytes $MemoryMaximumBytes
        
        # Set number of CPU cores
        Set-VMProcessor -VMName $VMName -Count $CPUCoreAllocate | Out-Null
        
        # Check if ISO exists before attaching
        if (Test-Path -Path $isoPath) {
            Write-Host "[+] Attaching ISO: $isoPath" -ForegroundColor Cyan
            Add-VMDvdDrive -VMName $VMName -Path $isoPath | Out-Null
        } else {
            Write-Host "[!] Warning: ISO file not found at $isoPath" -ForegroundColor Yellow
        }
       
        # Configure firmware settings based on OS type
        if ($enableSecureBoot) {
            Write-Host "[+] Enabling Secure Boot" -ForegroundColor Cyan
            Set-VMFirmware -VMName $VMName -EnableSecureBoot On | Out-Null
            # Add TPM for Windows 11 clients
            Write-Host "[+] Setting up TPM " -ForegroundColor Cyan
            # Create a key protector for the VM
            Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
            Enable-VMTPM -VMName $VMName | Out-Null
        } else {
            Write-Host "[+] Disabling Secure Boot for Linux compatibility" -ForegroundColor Cyan
            Set-VMFirmware -VMName $VMName -EnableSecureBoot Off | Out-Null
        }

        # Set boot order to DVD drive first
        try {
            Write-Host "[+] Setting boot order: DVD first" -ForegroundColor Cyan
            
            # Get the DVD drive
            $DVDDrive = Get-VMDvdDrive -VMName $VMName
            
            if ($DVDDrive) {
                # Get all boot entries
                $VMFirmware = Get-VMFirmware -VMName $VMName
                $BootOrder = $VMFirmware.BootOrder
                
                # Find the DVD device in the boot order
                $DVDEntry = $BootOrder | Where-Object { $_.Device -eq $DVDDrive }
                
                if ($DVDEntry) {
                    # Set DVD as first boot device
                    Set-VMFirmware -VMName $VMName -FirstBootDevice $DVDEntry
                    Write-Host "[+] Successfully set DVD as first boot device" -ForegroundColor Cyan
                } else {
                    Write-Host "[!] DVD entry not found in boot order. Trying alternative method..." -ForegroundColor Yellow
                    # If DVD entry is not found, we can set the first boot device directly
                    # Create a new boot order with DVD first
                    # Note: We can't directly manipulate BootOrder, we need to use FirstBootDevice
                    # for the DVD and let the system handle the rest
                    Set-VMFirmware -VMName $VMName -FirstBootDevice $DVDDrive
                    
                    Write-Host "[+] Set DVD drive as first boot device" -ForegroundColor Cyan
                }
            } else {
                Write-Host "[!] No DVD drive found for VM: $VMName" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] Error setting boot order: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Write-Host "[OK] Finished creating VM: $VMName" -ForegroundColor Green
    }
}

Write-Host "`n[OK] Script completed successfully!" -ForegroundColor Green

write-host "`n [+] Create Private Switch:" -ForegroundColor Blue

# Define Switch groups
$swGroups = @(
    @{ BaseName = "$SwitchBaseName 1"; },
    @{ BaseName = "$SwitchBaseName 2"; },
    @{ BaseName = "$SwitchBaseName 3"; }
    )
# Create Private Switches
foreach ($group in $swGroups){
    $baseName = $group.BaseName
    # Fix: Changed SVName to baseName
    New-VMSwitch -Name $baseName -SwitchType Private
    write-host "`n [+] Switch $baseName Created" -ForegroundColor Blue
}
}
# UNINSTALL SECTION
if ($Uninstall) {
    Write-Host "`n[+] Starting uninstall process..." -ForegroundColor Blue
    
    # Check if Hyper-V PowerShell module is available
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        Write-Host "[X] Hyper-V PowerShell module not found! Cannot perform uninstall." -ForegroundColor Red
        exit
    }
    
    # Get all VMs created by this script based on naming patterns
    $vmGroups = @(
        @{ Pattern = "$RouterBaseName *" },
        @{ Pattern = "$ServerBaseName *" },
        @{ Pattern = "$ClientBaseName *" }
    )
    
    $vmsToRemove = @()
    foreach ($group in $vmGroups) {
        $vmsToRemove += Get-VM -Name $group.Pattern -ErrorAction SilentlyContinue
    }
    
    # Confirm VM removal
    if ($vmsToRemove.Count -gt 0) {
        Write-Host "`nThe following VMs will be removed:" -ForegroundColor Yellow
        $vmsToRemove | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
        
        $confirm = Read-Host "`nAre you sure you want to remove these VMs? (Y/N)"
        if ($confirm -ne "Y" -and $confirm -ne "y") {
            Write-Host "[!] Uninstall canceled." -ForegroundColor Yellow
            exit
        }
        
        # Remove VMs
        foreach ($vm in $vmsToRemove) {
            Write-Host "[-] Removing VM: $($vm.Name)" -ForegroundColor DarkRed
            
            # Stop VM if running
            if ($vm.State -ne 'Off') {
                Write-Host "[-] Stopping VM..." -ForegroundColor DarkRed
                Stop-VM -Name $vm.Name -Force -TurnOff
            }
            
            # Get VM hard disks before removing the VM
            $vmHardDisks = Get-VMHardDiskDrive -VMName $vm.Name | Select-Object -ExpandProperty Path
            
            # Remove the VM
            Remove-VM -Name $vm.Name -Force
            
            # Remove associated VHD files
            foreach ($disk in $vmHardDisks) {
                if (Test-Path -Path $disk) {
                    Write-Host "[-] Removing disk: $disk" -ForegroundColor DarkRed
                    Remove-Item -Path $disk -Force
                }
            }
            
            # Remove VM folder
            $vmPath = Join-Path -Path $VMPath -ChildPath $vm.Name
            if (Test-Path -Path $vmPath) {
                Write-Host "[-] Removing VM folder: $vmPath" -ForegroundColor DarkRed
                Remove-Item -Path $vmPath -Recurse -Force
            }
        }
    } else {
        Write-Host "[!] No matching VMs found to remove." -ForegroundColor Yellow
    }
    
    # Remove private switches
    $switchPatterns = @("$SwitchBaseName *")
    foreach ($pattern in $switchPatterns) {
        $switchesToRemove = Get-VMSwitch -Name $pattern -ErrorAction SilentlyContinue
        
        if ($switchesToRemove.Count -gt 0) {
            Write-Host "`nRemoving virtual switches:" -ForegroundColor Yellow
            $switchesToRemove | ForEach-Object { 
                Write-Host "[-] Removing switch: $($_.Name)" -ForegroundColor DarkRed
                Remove-VMSwitch -Name $_.Name -Force
            }
        }
    }
    
    # Ask to remove VM and VHD directories
    $cleanupDirs = Read-Host "`nDo you want to remove the Hyper-V directories ($VMPath and $VHDPath)? (Y/N)"
    if ($cleanupDirs -eq "Y" -or $cleanupDirs -eq "y") {
        $directories = @($VMPath, "$VHDPath")
        foreach ($dir in $directories) {
            if (Test-Path -Path $dir) {
                Write-Host "[-] Removing directory: $dir" -ForegroundColor DarkRed
                Remove-Item -Path $dir -Recurse -Force
            }
        }
        
        # Remove parent directory if it's empty
    $cleanupRootDir = Read-Host "`nDo you want to remove the Hyper-V Root Directory? ($VMRootPath)? (Y/N)"
        if (($cleanupRootDir -eq "Y" -or $cleanupDirs -eq "y") -and (Test-Path -Path $VMRootPath)) {
            $items = Get-ChildItem -Path $VMRootPath -ErrorAction SilentlyContinue
            if (-not $items) {
                Write-Host "[-] Removing empty parent directory: $VMRootPath" -ForegroundColor DarkRed
                Remove-Item -Path $VMRootPath -Force
            }
        }
    }
    
    Write-Host "`n[OK] Uninstall completed successfully!" -ForegroundColor Green
    exit
}