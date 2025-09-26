Param(
        [parameter(Mandatory = $false)]
        [string]
        $IdentityDomainName, 

        [parameter(Mandatory)]
        [string]
        $AmdVmSize, 

        [parameter(Mandatory)]
        [string]
        $IdentityServiceProvider,

        [parameter(Mandatory)]
        [string]
        $FSLogix,

        [parameter(Mandatory = $false)]
        [string]
        $FSLogixStorageAccountKey,

        [parameter(Mandatory = $false)]
        [string]
        $FSLogixFileShare,

        [parameter(Mandatory)]
        [string]
        $HostPoolRegistrationToken,    

        [parameter(Mandatory)]
        [string]
        $NvidiaVmSize,

        [parameter(Mandatory = $false)]
        [string]
        $ExtendOsDisk

        # [parameter(Mandatory)]
        # [string]
        # $ScreenCaptureProtection
)

function New-Log {
        Param (
                [Parameter(Mandatory = $true, Position = 0)]
                [string] $Path
        )
    
        $date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"
        Set-Variable logFile -Scope Script
        $script:logFile = "$Script:Name-$date.log"
    
        if ((Test-Path $path ) -eq $false) {
                $null = New-Item -Path $path -ItemType directory
        }
    
        $script:Log = Join-Path $path $logfile
    
        Add-Content $script:Log "Date`t`t`tCategory`t`tDetails"
}
function Write-Log {
        Param (
                [Parameter(Mandatory = $false, Position = 0)]
                [ValidateSet("Info", "Warning", "Error")]
                $Category = 'Info',
                [Parameter(Mandatory = $true, Position = 1)]
                $Message
        )
    
        $Date = get-date
        $Content = "[$Date]`t$Category`t`t$Message`n" 
        Add-Content $Script:Log $content -ErrorAction Stop
        If ($Verbose) {
                Write-Verbose $Content
        }
        Else {
                Switch ($Category) {
                        'Info' { Write-Host $content }
                        'Error' { Write-Error $Content }
                        'Warning' { Write-Warning $Content }
                }
        }
}
function Copy-FixFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    if (-not (Test-Path -Path $Source)) {
        Write-Log -Category 'Warning' -Message "Source not found: $Source"
        return
    }

    try {
        # Always recurse — works for both files and folders
        Copy-Item -Path $Source -Destination $Destination -Force -Recurse -ErrorAction Stop
        Write-Log -Category 'Info' -Message "Copied $Source → $Destination"
    }
    catch {
        Write-Log -Category 'Error' -Message "Failed to copy $Source → ${Destination}: $_"
    }
}
function Get-WebFile {
        param(
                [parameter(Mandatory)]
                [string]$FileName,

                [parameter(Mandatory)]
                [string]$URL
        )
        $Counter = 0
        do {
                Invoke-WebRequest -Uri $URL -OutFile $FileName -ErrorAction 'SilentlyContinue'
                if ($Counter -gt 0) {
                        Start-Sleep -Seconds 30
                }
                $Counter++
        }
        until((Test-Path $FileName) -or $Counter -eq 9)
}

Function Set-RegistryValue {
        [CmdletBinding()]
        param (
                [Parameter()]
                [string]
                $Name,
                [Parameter()]
                [string]
                $Path,
                [Parameter()]
                [string]$PropertyType,
                [Parameter()]
                $Value
        )
        Begin {
                Write-Log -message "[Set-RegistryValue]: Setting Registry Value: $Name"
        }
        Process {
                # Create the registry Key(s) if necessary.
                If (!(Test-Path -Path $Path)) {
                        Write-Log -message "[Set-RegistryValue]: Creating Registry Key: $Path"
                        New-Item -Path $Path -Force | Out-Null
                }
                # Check for existing registry setting
                $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
                If ($RemoteValue) {
                        # Get current Value
                        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
                        Write-Log -message "[Set-RegistryValue]: Current Value of $($Path)\$($Name) : $CurrentValue"
                        If ($Value -ne $CurrentValue) {
                                Write-Log -message "[Set-RegistryValue]: Setting Value of $($Path)\$($Name) : $Value"
                                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
                        }
                        Else {
                                Write-Log -message "[Set-RegistryValue]: Value of $($Path)\$($Name) is already set to $Value"
                        }           
                }
                Else {
                        Write-Log -message "[Set-RegistryValue]: Setting Value of $($Path)\$($Name) : $Value"
                        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
                }
                Start-Sleep -Milliseconds 500
        }
        End {
        }
}
function Set-ListPolicy($baseKey, [string[]]$items) {
    # Creates subkey where values "1","2",... are REG_SZ entries
    # Clears existing numeric entries first
    New-EdgeKey $baseKey
    Get-ItemProperty -Path $baseKey -ErrorAction SilentlyContinue | Out-Null
    Get-ChildItem -Path $baseKey -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.PSChildName -match '^\d+$') { Remove-ItemProperty -Path $baseKey -Name $_.PSChildName -ErrorAction SilentlyContinue }
    }
    $i = 1
    foreach ($item in $items) {
        New-ItemProperty -Path $baseKey -Name $i -PropertyType String -Value $item -Force | Out-Null
    $i++
    }
}

function New-EdgeKey($path) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        }

function Set-FixedPagefile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z]$')]
        [string] $DriveLetter,

        [Parameter(Mandatory)]
        [ValidateRange(256, 65536)]
        [uint32] $InitialSizeMB,

        [Parameter(Mandatory)]
        [ValidateRange(256, 65536)]
        [uint32] $MaximumSizeMB
    )

    try {
        Write-Log -Message "Disabling automatic pagefile.sys management" -Category 'Info'
        Set-CimInstance -Query "SELECT * FROM Win32_ComputerSystem" -Property @{ AutomaticManagedPagefile = $false }

        # Remove any existing pagefile entries on C: and target drive
        foreach ($pf in @("C:\pagefile.sys", "$DriveLetter`:\pagefile.sys")) {
            try {
                Get-CimInstance -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='$pf'" |
                    Remove-CimInstance -ErrorAction Stop
                Write-Log -Message "Removed existing pagefile entry: $pf" -Category 'Info'
            }
            catch {
                Write-Log -Message "No existing pagefile found at $pf or removal failed: $_" -Category 'Warning'
            }
        }

        # Create new fixed-size pagefile
        $pagefilePath = "$DriveLetter`:\pagefile.sys"
        New-CimInstance -ClassName Win32_PageFileSetting -Property @{
            Name        = $pagefilePath
            InitialSize = $InitialSizeMB
            MaximumSize = $MaximumSizeMB
        } -ErrorAction Stop

        Write-Log -Message "Pagefile created on ${DriveLetter}: with fixed size $InitialSizeMB MB." -Category 'Info'
    }
    catch {
        Write-Log -Message "Failed to configure pagefile: $_" -Category 'Error'
        throw
    }
}

function Install-AVDAgent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $HostPoolRegistrationToken,

        [Parameter()]
        [string] $BootloaderUrl = 'https://go.microsoft.com/fwlink/?linkid=2311028',

        [Parameter()]
        [string] $AgentUrl = 'https://go.microsoft.com/fwlink/?linkid=2310011',

        [Parameter()]
        [string] $BootloaderFile = 'AVD-Bootloader.msi',

        [Parameter()]
        [string] $AgentFile = 'AVD-Agent.msi'
    )

    try {
        # Descargar e instalar Bootloader
        try {
            Write-Log -Message "Downloading AVD Bootloader from $BootloaderUrl" -Category 'Info'
            Get-WebFile -FileName $BootloaderFile -URL $BootloaderUrl

            Write-Log -Message "Installing AVD Bootloader" -Category 'Info'
            Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $BootloaderFile /quiet /qn /norestart /passive" -Wait -ErrorAction Stop
            Write-Log -Message "Installed AVD Bootloader successfully" -Category 'Info'
        }
        catch {
            Write-Log -Message "Failed to install AVD Bootloader: $_" -Category 'Error'
            throw
        }

        Start-Sleep -Seconds 5

        # Descargar e instalar Agent
        try {
            Write-Log -Message "Downloading AVD Agent from $AgentUrl" -Category 'Info'
            Get-WebFile -FileName $AgentFile -URL $AgentUrl

            Write-Log -Message "Installing AVD Agent" -Category 'Info'
            Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $AgentFile /quiet /qn /norestart /passive REGISTRATIONTOKEN=$HostPoolRegistrationToken" -Wait -ErrorAction Stop
            Write-Log -Message "Installed AVD Agent successfully" -Category 'Info'
        }
        catch {
            Write-Log -Message "Failed to install AVD Agent: $_" -Category 'Error'
            throw
        }

        Start-Sleep -Seconds 5
    }
    catch {
        Write-Log -Message "AVD installation process failed: $_" -Category 'Error'
        throw
    }
}

function Copy-FixFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $Source,

        [Parameter(Mandatory)]
        [string] $Destination,

        [switch] $Recurse
    )

    if (-not (Test-Path -Path $Source)) {
        Write-Log -Message "Source not found: $Source" -Category 'Warning'
        return
    }

    try {
        Copy-Item -Path -Source $Source -Destination $Destination -Force -Recurse:$Recurse -ErrorAction Stop
        Write-Log -Message "Copied $Source → $Destination" -Category 'Info'
    }
    catch {
        Write-Log -Path $LogPath -Message "Failed to copy $Source → ${Destination}: $_" -Category 'Error'
    }
}

$ErrorActionPreference = 'Stop'
$Script:Name = 'Set-SessionHostConfiguration'
New-Log -Path (Join-Path -Path $env:SystemRoot -ChildPath 'Logs')
try {

        ##############################################################
        #  Add Recommended AVD Settings
        ##############################################################
        $Settings = @(

                # Disable Automatic Updates: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#disable-automatic-updates
                [PSCustomObject]@{
                        Name         = 'NoAutoUpdate'
                        Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
                        PropertyType = 'DWord'
                        Value        = 1
                }

                # Enable Time Zone Redirection: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
                # [PSCustomObject]@{
                #         Name         = 'fEnableTimeZoneRedirection'
                #         Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                #         PropertyType = 'DWord'
                #         Value        = 1
                # }
        )

        ##############################################################
        #  Add GPU Settings
        ##############################################################
        # This setting applies to the VM Size's recommended for AVD with a GPU
        if ($AmdVmSize -eq 'true' -or $NvidiaVmSize -eq 'true') {
                $Settings += @(

                        # Configure GPU-accelerated app rendering: https://docs.microsoft.com/en-us/azure/virtual-desktop/configure-vm-gpu#configure-gpu-accelerated-app-rendering
                        [PSCustomObject]@{
                                Name         = 'bEnumerateHWBeforeSW'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        # Configure fullscreen video encoding: https://docs.microsoft.com/en-us/azure/virtual-desktop/configure-vm-gpu#configure-fullscreen-video-encoding
                        [PSCustomObject]@{
                                Name         = 'AVC444ModePreferred'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        [PSCustomObject]@{
                                Name         = 'KeepAliveEnable'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        [PSCustomObject]@{
                                Name         = 'KeepAliveInterval'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        [PSCustomObject]@{
                                Name         = 'MinEncryptionLevel'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 3
                        },
                        [PSCustomObject]@{
                                Name         = 'AVCHardwareEncodePreferred'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        }
                )
        }
        # This setting applies only to VM Size's recommended for AVD with a Nvidia GPU
        if ($NvidiaVmSize -eq 'true') {
                $Settings += @(

                        # Configure GPU-accelerated frame encoding: https://docs.microsoft.com/en-us/azure/virtual-desktop/configure-vm-gpu#configure-gpu-accelerated-frame-encoding
                        [PSCustomObject]@{
                                Name         = 'AVChardwareEncodePreferred'
                                Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                                PropertyType = 'DWord'
                                Value        = 1
                        }
                )
        }

        # ##############################################################
        # #  Add Screen Capture Protection Setting
        # ##############################################################
        # if ($ScreenCaptureProtection -eq 'true') {
        #         $Settings += @(

        #                 # Enable Screen Capture Protection: https://docs.microsoft.com/en-us/azure/virtual-desktop/screen-capture-protection
        #                 [PSCustomObject]@{
        #                         Name         = 'fEnableScreenCaptureProtect'
        #                         Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        #                         PropertyType = 'DWord'
        #                         Value        = 1
        #                 }
        #         )
        # }

        ##############################################################
        #  Add Fslogix Settings
        ##############################################################
        if ($Fslogix -eq 'true') {
                $FSLogixStorageFQDN = $FSLogixFileShare.Split('\')[2]                
                $Settings += @(
                        # Enables Fslogix profile containers: https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#enabled
                        [PSCustomObject]@{
                                Name         = 'Enabled'
                                Path         = 'HKLM:\SOFTWARE\Fslogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        # Deletes a local profile if it exists and matches the profile being loaded from VHD: https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#deletelocalprofilewhenvhdshouldapply
                        [PSCustomObject]@{
                                Name         = 'DeleteLocalProfileWhenVHDShouldApply'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        # The folder created in the Fslogix fileshare will begin with the username instead of the SID: https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#flipflopprofiledirectoryname
                        [PSCustomObject]@{
                                Name         = 'FlipFlopProfileDirectoryName'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 1
                        },
                        # # Loads FRXShell if there's a failure attaching to, or using an existing profile VHD(X): https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#preventloginwithfailure
                        # [PSCustomObject]@{
                        #         Name         = 'PreventLoginWithFailure'
                        #         Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                        #         PropertyType = 'DWord'
                        #         Value        = 1
                        # },
                        # # Loads FRXShell if it's determined a temp profile has been created: https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#preventloginwithtempprofile
                        # [PSCustomObject]@{
                        #         Name         = 'PreventLoginWithTempProfile'
                        #         Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                        #         PropertyType = 'DWord'
                        #         Value        = 1
                        # },
                        # List of file system locations to search for the user's profile VHD(X) file: https://docs.microsoft.com/en-us/fslogix/profile-container-configuration-reference#vhdlocations
                        [PSCustomObject]@{
                                Name         = 'VHDLocations'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'MultiString'
                                Value        = $FSLogixFileShare
                        },
                        [PSCustomObject]@{
                                Name         = 'VolumeType'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'String'
                                Value        = 'vhdx'
                        },
                        [PSCustomObject]@{
                                Name         = 'LockedRetryCount'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 3
                        },
                        [PSCustomObject]@{
                                Name         = 'LockedRetryInterval'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 15
                        },
                        [PSCustomObject]@{
                                Name         = 'ReAttachIntervalSeconds'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 15
                        },
                        [PSCustomObject]@{
                                Name         = 'ReAttachRetryCount'
                                Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                PropertyType = 'DWord'
                                Value        = 3
                        }
                )
                if ($IdentityServiceProvider -eq "EntraIDKerberos" -and $Fslogix -eq 'true') {
                        $Settings += @(
                                [PSCustomObject]@{
                                        Name         = 'CloudKerberosTicketRetrievalEnabled'
                                        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
                                        PropertyType = 'DWord'
                                        Value        = 1
                                },
                                [PSCustomObject]@{
                                        Name         = 'LoadCredKeyFromProfile'
                                        Path         = 'HKLM:\Software\Policies\Microsoft\AzureADAccount'
                                        PropertyType = 'DWord'
                                        Value        = 1
                                },
                                [PSCustomObject]@{
                                        Name         = $IdentityDomainName
                                        Path         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\domain_realm'
                                        PropertyType = 'String'
                                        Value        = $FSLogixStorageFQDN
                                }

                        )
                }
                If ($FsLogixStorageAccountKey -ne '') {                
                        $SAName = $FSLogixStorageFQDN.Split('.')[0]
                        Write-Log -Message "Adding Local Storage Account Key for '$FSLogixStorageFQDN' to Credential Manager" -Category 'Info'
                        $CMDKey = Start-Process -FilePath 'cmdkey.exe' -ArgumentList "/add:$FSLogixStorageFQDN /user:localhost\$SAName /pass:$FSLogixStorageAccountKey" -Wait -PassThru
                        If ($CMDKey.ExitCode -ne 0) {
                                Write-Log -Message "CMDKey Failed with '$($CMDKey.ExitCode)'. Failed to add Local Storage Account Key for '$FSLogixStorageFQDN' to Credential Manager" -Category 'Error'
                        }
                        Else {
                                Write-Log -Message "Successfully added Local Storage Account Key for '$FSLogixStorageFQDN' to Credential Manager" -Category 'Info'
                        }
                        $Settings += @(
                                # Attach the users VHD(x) as the computer: https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles#accessnetworkascomputerobject
                                [PSCustomObject]@{
                                        Name         = 'AccessNetworkAsComputerObject'
                                        Path         = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                                        PropertyType = 'DWord'
                                        Value        = 1
                                }                                
                        )
                        $Settings += @(
                                # Disable Roaming the Recycle Bin because it corrupts. https://learn.microsoft.com/en-us/fslogix/reference-configuration-settings?tabs=profiles#roamrecyclebin
                                [PSCustomObject]@{
                                        Name         = 'RoamRecycleBin'
                                        Path         = 'HKLM:\SOFTWARE\FSLogix\Apps'
                                        PropertyType = 'DWord'
                                        Value        = 0
                                }
                        )
                        # Disable the Recycle Bin
                        Reg LOAD "HKLM\TempHive" "$env:SystemDrive\Users\Default User\NtUser.dat"
                        Set-RegistryValue -Path 'HKLM:\TempHive\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoRecycleFiles -PropertyType DWord -Value 1
                        Write-Log -Message "Unloading default user hive."
                        $null = cmd /c REG UNLOAD "HKLM\TempHive" '2>&1'
                        If ($LastExitCode -ne 0) {
                                # sometimes the registry doesn't unload properly so we have to perform powershell garbage collection first.
                                [GC]::Collect()
                                [GC]::WaitForPendingFinalizers()
                                Start-Sleep -Seconds 5
                                $null = cmd /c REG UNLOAD "HKLM\TempHive" '2>&1'
                                If ($LastExitCode -eq 0) {
                                        Write-Log -Message "Hive unloaded successfully."
                                }
                                Else {
                                        Write-Log -category Error -Message "Default User hive unloaded with exit code [$LastExitCode]."
                                }
                        }
                        Else {
                                Write-Log -Message "Hive unloaded successfully."
                        }
                }
                $LocalAdministrator = (Get-LocalUser | Where-Object { $_.SID -like '*-500' }).Name
                $LocalGroups = 'FSLogix Profile Exclude List', 'FSLogix ODFC Exclude List'
                ForEach ($Group in $LocalGroups) {
                        If (-not (Get-LocalGroupMember -Group $Group | Where-Object { $_.Name -like "*$LocalAdministrator" })) {
                                Add-LocalGroupMember -Group $Group -Member $LocalAdministrator
                        }
                }
        }

        ##############################################################
        #  Add Microsoft Entra ID Join Setting
        ##############################################################
        if ($IdentityServiceProvider -match "EntraID") {
                $Settings += @(

                        # Enable PKU2U: https://docs.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-azure-ad-connections#windows-desktop-client
                        [PSCustomObject]@{
                                Name         = 'AllowOnlineID'
                                Path         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
                                PropertyType = 'DWord'
                                Value        = 1
                        }
                )
        }

        # Set registry settings
        foreach ($Setting in $Settings) {
                Set-RegistryValue -Name $Setting.Name -Path $Setting.Path -PropertyType $Setting.PropertyType -Value $Setting.Value -Verbose
        }

        # Resize OS Disk

        if ($ExtendOsDisk -eq 'true') {
                Write-Log -message "Resizing OS Disk"
                $driveLetter = $env:SystemDrive.Substring(0, 1)
                $size = Get-PartitionSupportedSize -DriveLetter $driveLetter
                Resize-Partition -DriveLetter $driveLetter -Size $size.SizeMax
                Write-Log -message "OS Disk Resized"
        }

        ##############################################################
        # Add Defender Exclusions for FSLogix 
        ##############################################################
        # https://docs.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop-fslogix#antivirus-exclusions
        if ($Fslogix -eq 'false') {

                $Files = @(
                        "%ProgramFiles%\FSLogix\Apps\frxdrv.sys",
                        "%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys",
                        "%ProgramFiles%\FSLogix\Apps\frxccd.sys",
                        "%TEMP%\*.VHD",
                        "%TEMP%\*.VHDX",
                        "%Windir%\TEMP\*.VHD",
                        "%Windir%\TEMP\*.VHDX",
                        "$FslogixFileShareName\*.VHD",
                        "$FslogixFileShareName\*.VHDX",
                        "%ProgramFiles%\Epic",
                        "$env:LOCALAPPDATA\Hyperdrive",
                        "$env:LOCALAPPDATA\Hyperdrive\EBWebView",
                        "$env:PROGRAMDATA\HyperdriveTempData"
                )

                foreach ($File in $Files) {
                        Add-MpPreference -ExclusionPath $File
                }
                Write-Log -Message 'Enabled Defender exlusions for FSLogix paths' -Category 'Info'

                $Processes = @(
                        "%ProgramFiles%\FSLogix\Apps\frxccd.exe",
                        "%ProgramFiles%\FSLogix\Apps\frxccds.exe",
                        "%ProgramFiles%\FSLogix\Apps\frxsvc.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\Core\win-x86\EpicDumpTruckInjector.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\Core\win-x86\DumpTruck\EpicDumpTruckInjector64.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Hyperdrive\Hyperdrive.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\VersionIndependent\Hyperspace.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\VersionIndependent\Launcher.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\EpicPDFSpooler.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\HubFramework.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\Core\win-x86\HubCore.exe",
                        "%ProgramFiles%\Epic\Hyperdrive\*\Bin\Core\win-x86\HubSpoke.exe"
                                )

                foreach ($Process in $Processes) {
                        Add-MpPreference -ExclusionProcess $Process
                }
                Write-Log -Message 'Enabled Defender exlusions for FSLogix processes' -Category 'Info'
        }

        ##############################################################
        #  Language and region settings applied
        ##############################################################
        
        Set-WinUILanguageOverride -Language fi-FI
        Set-WinUserLanguageList fi-FI -Force
        Set-WinSystemLocale fi-FI
        Set-Culture fi-FI
        Set-WinHomeLocation -GeoId 77
        Copy-UserInternationalSettingsToSystem -WelcomeScreen $False -NewUser $True
        Write-Log -Message 'Language, locales, culture and region configured' -Category 'Info'


        # ----------------------------------------------
        # TELEMETRY & PRIVACY related registry settings
        # ----------------------------------------------
        Write-Log -Message "Applying Windows privacy & telemetry hardening" -Category 'Info'

        $regSettings = @(
        # 1) TELEMETRY
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DisableEnterpriseAuthProxy"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"; Name = "UserCritEtwOptOut"; PropertyType = "DWord"; Value = 1 },

        # 2) CONSUMER EXPERIENCES
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; PropertyType = "DWord"; Value = 1 },

        # 3) GEOLOCATION
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableWindowsLocationProvider"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocationScripting"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessLocation"; PropertyType = "DWord"; Value = 2 },

        # 4) FIND MY DEVICE
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice"; Name = "AllowFindMyDevice"; PropertyType = "DWord"; Value = 0 },

        # 5) HANDWRITING / TYPING IMPROVEMENT
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "AllowInputPersonalization"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; PropertyType = "DWord"; Value = 1 },

        # 6) ADS / ADVERTISING ID / SEARCH
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableSearchHistory"; PropertyType = "DWord"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCloudSearch"; PropertyType = "DWord"; Value = 0 },

        # 7) FIRST SIGN-IN ANIMATION / PRIVACY EXPERIENCE
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableFirstLogonAnimation"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "EnableFirstLogonAnimation"; PropertyType = "DWord"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"; Name = "DisablePrivacyExperience"; PropertyType = "DWord"; Value = 1 }
        )

        # -------------------------------
        # Apply all settings
        # -------------------------------
        foreach ($setting in $regSettings) {
        Set-RegistryValue -Path $setting.Path -Name $setting.Name -PropertyType $setting.PropertyType -Value $setting.Value
        }

        Write-Log -Message "Windows privacy & telemetry hardening complete" -Category 'Info'

        ##############################################################
        # Session Timeouts
        ##############################################################
        New-Item -ItemType Directory -Force -Path "C:\AIB"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/ConfigureSessionTimeoutsV2.ps1" -OutFile "C:\AIB\ConfigureSessionTimeoutsV2.ps1"
        & "C:\AIB\ConfigureSessionTimeoutsV2.ps1" -MaxDisconnectionTime 5 -MaxIdleTime 120 -RemoteAppLogoffTimeLimit 15 -fResetBroken "1"

        ##############################################################
        # Edge hardening
        ##############################################################

        $edgeReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

        Write-Log -Message "Applying Edge hardening to $edgeReg" -Category 'Info'

        # --- Extensions: block everything by default ---
        $blocklistKey = Join-Path $edgeReg 'ExtensionInstallBlocklist'
        Set-ListPolicy -baseKey $blocklistKey -items @('*')  # block all

        # --- Registry settings to apply ---
        $edgeSettings = @(
        @{ Name = 'AutofillAddressEnabled';              PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'AutofillCreditCardEnabled';           PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'PasswordManagerEnabled';              PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'PasswordMonitorAllowed';              PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'SearchSuggestEnabled';                PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'AddressBarTrendingSuggestEnabled';    PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'ClearBrowsingDataOnExit';             PropertyType = 'DWord'; Value = 1 },
        @{ Name = 'HideFirstRunExperience';              PropertyType = 'DWord'; Value = 1 },
        @{ Name = 'MicrosoftEditorProofingEnabled';      PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'AddressBarEditingEnabled';            PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'DefaultCookiesSetting';               PropertyType = 'DWord'; Value = 4 },
        @{ Name = 'EnableMediaRouter';                   PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'HideFirstRunExperience';              PropertyType = 'DWord'; Value = 1 },
        @{ Name = 'DefaultBrowserSettingEnabled';        PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'BrowserSignin';                       PropertyType = 'DWord'; Value = 0 },
        @{ Name = 'DefaultNotificationsSetting';         PropertyType = 'DWord'; Value = 2 }
        )

        foreach ($setting in $edgeSettings) {
        Set-RegistryValue -Path $edgeReg -Name $setting.Name -PropertyType $setting.PropertyType -Value $setting.Value
        }

        try {
        Set-RegistryValue `
                -Name 'Update {56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' `
                -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' `
                -PropertyType DWord `
                -Value 0
        Write-Log -Category 'Info' -Message "Edge auto-update policy applied successfully."
        }
        catch {
        Write-Log -Category 'Error' -Message "Failed to set Edge auto-update policy: $_"
        }

        ##############################################################
        # Windows Optimizations
        ##############################################################
        New-Item -ItemType Directory -Force -Path "C:\AIB"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/WindowsOptimization.ps1" -OutFile "C:\AIB\WindowsOptimization.ps1"
        & "C:\AIB\WindowsOptimization.ps1" -Optimizations "WindowsMediaPlayer","DefaultUserSettings","Autologgers","Services"      

        ##############################################################
        # File Updater & cleanup
        ##############################################################
 <#        #Issue 27: Copy Config.json for Epic Hyperdrive
        $sourceItem = "C:\AIB\software\Hyperdrive\Epic Hyperdrive Setup 100.2508.0\491Config.json"
        $targetFolder = "C:\Program Files (x86)\Epic\Hyperdrive\Config"

        Copy-FixFile -Source $sourceItem -Destination $targetFolder

        #Issue 25: Copy FileZilla configuration file
        $sourceItem = "C:\AIB\software\FileZilla\fzdefaults.xml"
        $targetFolder = "C:\Program Files\FileZilla FTP Client"
        
        Copy-FixFile -Source $sourceItem -Destination $targetFolder



        # Issue 1
        New-Item -ItemType Directory -Force -Path C:\\Sovellukset\Hyperdrive
        New-Item -ItemType Directory -Force -Path C:\\Sovellukset\tukiportaali

        $sourceItem = "C:\AIB\\software\\LastConfigurations\\Hyperdrive"
        $targetFolder = "C:\Sovellukset"
        Copy-FixFile -Source $sourceItem -Destination $targetFolder


        $sourceItem = "C:\AIB\software\\LastConfigurations\\tukiportaali"
        $targetFolder = "C:\Sovellukset"
        Copy-FixFile -Source $sourceItem -Destination $targetFolder #>

        $fixes = @(
        [PSCustomObject]@{ Issue = 27; Description = "Epic Hyperdrive Config"; Source = "C:\AIB\software\Hyperdrive\Epic Hyperdrive Setup 100.2508.0\491Config.json"; Destination = "C:\Program Files (x86)\Epic\Hyperdrive\Config" },
        [PSCustomObject]@{ Issue = 25; Description = "FileZilla config"; Source = "C:\AIB\software\FileZilla\fzdefaults.xml"; Destination = "C:\Program Files\FileZilla FTP Client" },
        [PSCustomObject]@{ Issue = 1; Description = "Hyperdrive bat script"; Source = "C:\AIB\software\LastConfigurations\Hyperdrive"; Destination = "C:\Sovellukset" },
        [PSCustomObject]@{ Issue = 1; Description = "Edge-Apotti-tukiportaali"; Source = "C:\AIB\software\LastConfigurations\tukiportaali"; Destination = "C:\Sovellukset" }
        )

        foreach ($fix in $fixes) {
        Write-Log -Category 'Info' -Message "Applying fix for Issue $($fix.Issue): $($fix.Description)"
        Copy-FixFile -Source $fix.Source -Destination $fix.Destination
        }

<#         # Clean up
        $pathsToClean = "C:\\AIB"
        foreach ($path in $($pathsToClean)) { 
                if (Test-Path $path) { 
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue 
                } 
        }#>

        ##############################################################
        # Fixed pagefile on D: and remove any on C:
        ##############################################################

        Set-FixedPagefile -DriveLetter 'D' -InitialSizeMB 10240 -MaximumSizeMB 10240

        ##############################################################
        #  Install the AVD Agent
        ##############################################################

        Install-AVDAgent -HostPoolRegistrationToken $HostPoolRegistrationToken
        

        ##############################################################
        #  Restart VM
        ##############################################################
        Restart-Computer -Force -Delay 30 
}
catch {
        Write-Log -Message $_ -Category 'Error'
        throw
}
