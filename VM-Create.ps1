# Check for elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[X] Missing Privileges! Restarting as administrator..." -ForegroundColor Green
    # Relaunch script as administrator
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Automatically get the first available virtual switch (testing)
$SwitchName = (Get-VMSwitch)[0].Name

# Common Configuration
$VMPath = "C:\Hyper-V\VMs"
$VHDPath = "C:\Hyper-V\VHDs"
#For windows 11 make sure you have at last 4GB ram 
$MemoryMinimumBytes = 512MB
$MemoryMaximumBytes = 2GB  
$MemoryStartupBytes = 1GB  # Must be within min and max
$VHDSizeBytes = 64GB
$CPUCoerAlocate = 2
$ISO_Client = "C:\ISOs\windowns.iso" #Client iso path
$ISO_Server = "C:\ISOs\linux.iso" #Server iso path

# Define VM groups
$vmGroups = @(
    @{ BaseName = "Linux - Router"; Count = 2; ISO = $ISO_Server }, # by modifying the number, you can change how many VMs are made 
    @{ BaseName = "Linux - Server"; Count = 5; ISO = $ISO_Server },
    @{ BaseName = "Win - Client"; Count = 2; ISO = $ISO_Client }
)

# Create VMs
foreach ($group in $vmGroups) {
    $baseName = $group.BaseName
    $count = $group.Count
    $isoPath = $group.ISO

    for ($i = 1; $i -le $count; $i++) {
        $VMName = "$baseName $i"
        $VMStoragePath = Join-Path -Path $VMPath -ChildPath $VMName
        $VHDFile = Join-Path -Path $VHDPath -ChildPath "$VMName.vhdx"

        Write-Host "`n[+] Starting creation of VM: $VMName" -ForegroundColor Cyan

        # Create folders
        New-Item -ItemType Directory -Path $VMStoragePath -Force | Out-Null

        # Create Virtual-HD
        New-VHD -Path $VHDFile -SizeBytes $VHDSizeBytes -Dynamic | Out-Null

        # Create Generation 2 VM
        New-VM -Name $VMName -Generation $CPUCoerAlocate -MemoryStartupBytes $MemoryStartupBytes -VHDPath $VHDFile -Path $VMStoragePath -SwitchName $SwitchName | Out-Null

        # Configure Dynamic Memory
        Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes $MemoryMinimumBytes -MaximumBytes $MemoryMaximumBytes

        # Set number of CPU cores, 2 by default 
        Set-VMProcessor -VMName $VMName -Count 2 | Out-Null

        # Attach ISO
        Add-VMDvdDrive -VMName $VMName -Path $isoPath | Out-Null

        # Enable Secure Boot for Windows only
        if ($baseName -like "Win") {
        Set-VMFirmware -VMName $VMName -EnableSecureBoot On | Out-Null
        }

        # Add TPM for Windows clients 
        if ($baseName -like "Win") {
            Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true | Out-Null
            # Create a key protector for the VM
            Set-VMKeyProtector -VMName $VMName -NewLocalKeyProtector
            Enable-VMTPM -VMName $VMName | Out-Null
        }
        
        Write-Host "[OK] Finished creating VM: $VMName" -ForegroundColor Green
    }
}
