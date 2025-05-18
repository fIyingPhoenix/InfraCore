# Check for elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[X] Missing privileges! Restarting as administrator..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Check if Hyper-V is installed
if (-not (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)) {
    Write-Host "[X] Hyper-V PowerShell module not found! Please ensure Hyper-V is installed." -ForegroundColor Red
    exit
}

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

# Common Configuration
$VMPath = "C:\Hyper-V\VMs"
$VHDPath = "C:\Hyper-V\VHDs"
$MemoryMinimumBytes = 512MB
$MemoryMaximumBytes = 2GB  
$MemoryStartupBytes = 1GB
$VHDSizeBytes = 64GB
$CPUCoreAllocate = 2

# Ensure ISOs point to different files as needed
$ISO_Client = "d:\ISOs\client.iso"
$ISO_Server = "d:\ISOs\server.iso"


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
    @{ BaseName = "Linux - Router"; Count = 2; ISO = $ISO_Server; EnableSecureBoot = $false },
    @{ BaseName = "Linux - Server"; Count = 5; ISO = $ISO_Server; EnableSecureBoot = $false },
    @{ BaseName = "Win - Client"; Count = 2; ISO = $ISO_Client; EnableSecureBoot = $true }
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
                    
                    # Alternative method - set boot order from scratch
                    $NetworkAdapters = Get-VMNetworkAdapter -VMName $VMName
                    $HDDPath = (Get-VMHardDiskDrive -VMName $VMName).Path
                    
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
    @{ BaseName = "PrivateSwitch 1"; },
    @{ BaseName = "PrivateSwitch 2"; },
    @{ BaseName = "PrivateSwitch 3"; }
    )
# Create VMs
foreach ($group in $swGroups){
    $baseName = $group.BaseName
    New-VMSwitch -Name $SVName -SwitchType Private
    write-host "`n [+] Swirch $baseName Created" -ForegroundColor Blue
}