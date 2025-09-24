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
        $ExtendOsDisk,

        [parameter(Mandatory = $false)]
        [string[]]
        $SaveCookiesOnExitUrls = @(),

        [parameter(Mandatory = $false)]
        [switch]
        $IsRemoteAppServer

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

Function New-EdgeKey($path) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

Function Set-DWord($path, $name, $value) {
        New-EdgeKey $path
        New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null
}

Function Set-ListPolicy($baseKey, [string[]]$items) {
        # Creates subkey where values "1","2",... are REG_SZ entries
        # Clears existing numeric entries first
        New-EdgeKey $baseKey
        Get-ItemProperty -Path $baseKey -ErrorAction SilentlyContinue | Out-Null
        Get-ChildItem -Path $baseKey -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.PSChildName -match '^\d+$') { 
                Remove-ItemProperty -Path $baseKey -Name $_.PSChildName -ErrorAction SilentlyContinue }
        }
        $i = 1
        foreach ($item in $items) {
                New-ItemProperty -Path $baseKey -Name $i -PropertyType String -Value $item -Force | Out-Null
                $i++
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
                },

                # Enable Time Zone Redirection: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image#set-up-time-zone-redirection
                [PSCustomObject]@{
                        Name         = 'fEnableTimeZoneRedirection'
                        Path         = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
                        PropertyType = 'DWord'
                        Value        = 1
                }
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
        #  Install the AVD Agent
        ##############################################################
        $BootInstaller = 'AVD-Bootloader.msi'
        Get-WebFile -FileName $BootInstaller -URL 'https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH'
        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $BootInstaller /quiet /qn /norestart /passive" -Wait -Passthru
        Write-Log -Message 'Installed AVD Bootloader' -Category 'Info'
        Start-Sleep -Seconds 5

        $AgentInstaller = 'AVD-Agent.msi'
        Get-WebFile -FileName $AgentInstaller -URL 'https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv'
        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $AgentInstaller /quiet /qn /norestart /passive REGISTRATIONTOKEN=$HostPoolRegistrationToken" -Wait -PassThru
        Write-Log -Message 'Installed AVD Agent' -Category 'Info'
        Start-Sleep -Seconds 5

        ##############################################################
        #  Restart VM
        ##############################################################
        if ($IdentityServiceProvider -eq "EntraIDKerberos" -and $AmdVmSize -eq 'false' -and $NvidiaVmSize -eq 'false') {
                Start-Process -FilePath 'shutdown' -ArgumentList '/r /t 30'
        }
        
        ##############################################################
        #  TimeZone and other settings applied
        ##############################################################
        Set-WinUILanguageOverride -Language fi-FI
        Set-WinUserLanguageList fi-FI -Force
        Set-WinSystemLocale fi-FI
        Set-Culture fi-FI
        Set-WinHomeLocation -GeoId 77
        Copy-UserInternationalSettingsToSystem -WelcomeScreen $False -NewUser $True
        Set-TimeZone -Id "FLE Standard Time"
        Write-Log -Message 'Set TimeZone and other locale settings' -Category 'Info'
        
        ##############################################################
        #  AVD Golden Image Hardening
        #  - Telemetry (policies)
        #  - Consumer Experiences (policy)
        #  - Geolocation (policies)
        #  - Find My Device (policy)
        #  - Improve handwriting/typing (policies)
        #  - Ads / Advertising ID + Tailored experiences (policies)
        #  - Reboot to apply pagefile
        ##############################################################

        # -------------------------------
        # 1) TELEMETRY (policies)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Type DWord -Value 1
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "UserCritEtwOptOut" -Type DWord -Value 1
        Write-Host "[OK] Telemetry hardened & DiagTrack disabled"

        # -------------------------------
        # 2) CONSUMER EXPERIENCES (policy)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
        Write-Host "[OK] Consumer experiences disabled"

        # -------------------------------
        # 3) GEOLOCATION (policies)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1

        # Block app access to location (Force Deny)
        # AppPrivacy policy values: 0 = User in control, 1 = Force allow, 2 = Force deny
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessLocation" -Type DWord -Value 2
        Write-Host "[OK] Geolocation disabled (system + apps)"

        # -------------------------------
        # 4) FIND MY DEVICE (policy)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Force | Out-Null
        # 0 = Off, 1 = On
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Type DWord -Value 0
        Write-Host "[OK] Find My Device disabled"

        # -------------------------------
        # 5) IMPROVE HANDWRITING / TYPING (policies)
        # -------------------------------
        # Input personalization (inking/typing learning & data collection)
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
        # 0 = Disallow personalization
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization"  -Type DWord -Value 0
        # Restrict implicit collections (1 = restrict/deny)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection"  -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
        # block handwriting data sharing
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
        Write-Host "[OK] Handwriting/Typing improvement disabled"

        # -------------------------------
        # 6) ADS / ADVERTISING ID (policies)
        # -------------------------------
        # Disable Advertising ID system-wide
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
        Write-Host "[OK] Advertising ID disabled"
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
        Write-Host "[OK] Cortana disabled"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableSearchHistory" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -PropertyType DWord -Force | Out-Null

        Write-Host "[OK] Windows Search History disabled"

        # -------------------------------
        # 7) FIRST SIGN-IN ANIMATION / PRIVACY SETTINGS EXPERIENCE (policies)
        # -------------------------------
        # 1) Disable First Sign-In Animation (policy key)
        $polSystem = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (-not (Test-Path $polSystem)) {
        New-Item -Path $polSystem -Force | Out-Null
        }
        New-ItemProperty -Path $polSystem -Name 'EnableFirstLogonAnimation' -PropertyType DWord -Value 0 -Force | Out-Null

        # (Optional/defensive) Also set Winlogon default key used by some builds/docs
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (-not (Test-Path $winlogon)) {
                New-Item -Path $winlogon | Out-Null
        }
        New-ItemProperty -Path $winlogon -Name 'EnableFirstLogonAnimation' -PropertyType DWord -Value 0 -Force | Out-Null

        # 2) Disable Privacy Settings Experience at sign-in (OOBE)
        $oobe = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE'
        New-Item -Path $oobe -Force | Out-Null
        New-ItemProperty -Path $oobe -Name 'DisablePrivacyExperience' -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Policies to prevent Sign-In Animation and Privacy Settings Experience set."

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"

        # Ensure the key exists
        if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
        }

        # Disable text and ink data collection
        New-ItemProperty -Path $regPath -Name "RestrictImplicitTextCollection" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "RestrictImplicitInkCollection"  -Value 1 -PropertyType DWord -Force | Out-Null

        # Block personalization features
        New-ItemProperty -Path $regPath -Name "AllowInputPersonalization" -Value 0 -PropertyType DWord -Force | Out-Null

        ##############################################################
        # Hardens Microsoft Edge on AVD session hosts for a golden image.
        ##############################################################

        $edgeReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Write-Host "Applying Edge hardening to $edgeReg"

        # --- Extensions: block everything by default ---
        $blocklistKey = Join-Path $edgeReg 'ExtensionInstallBlocklist'
        Set-ListPolicy -baseKey $blocklistKey -items @('*')  # block all

        # --- Autofill: addresses & cards ---
        Set-DWord $edgeReg 'AutofillAddressEnabled' 0
        Set-DWord $edgeReg 'AutofillCreditCardEnabled' 0

        # --- Password manager & Password Monitor ---
        Set-DWord $edgeReg 'PasswordManagerEnabled' 0
        Set-DWord $edgeReg 'PasswordMonitorAllowed' 0

        # --- Search suggestions & Bing trending ---
        Set-DWord $edgeReg 'SearchSuggestEnabled' 0
        # Optional but recommended on recent Edge (135+):
        Set-DWord $edgeReg 'AddressBarTrendingSuggestEnabled' 0

        # --- Clear all browsing data on exit ---
        Set-DWord $edgeReg 'ClearBrowsingDataOnExit' 1

        # --- Hide First Run Experience ---
        Set-DWord $edgeReg 'HideFirstRunExperience' 1

        # --- Disable Microsoft Editor cloud proofing (enhanced spell/grammar) ---
        Set-DWord $edgeReg 'MicrosoftEditorProofingEnabled' 0

        # --- Published-app-server (RemoteApp) lockdowns ---
        if ($IsRemoteAppServer) {
                Write-Host "Applying additional RemoteApp server controls..."

                # Disable address-bar editing (does NOT fully prevent navigation)
                Set-DWord $edgeReg 'AddressBarEditingEnabled' 0

                # Session-only cookies (except allowlist)
                Set-DWord $edgeReg 'DefaultCookiesSetting' 4

                # Disable Google Cast
                Set-DWord $edgeReg 'EnableMediaRouter' 0
        }

        # --- Optional: Cookie exceptions to persist across exit ---
        if ($SaveCookiesOnExitUrls.Count -gt 0) {
                $saveOnExitKey = Join-Path $edgeReg 'SaveCookiesOnExit'
                Set-ListPolicy -baseKey $saveOnExitKey -items $SaveCookiesOnExitUrls
        }

        Write-Host "Edge hardening complete. Some settings require Edge restart to take effect."

        ##############################################################
        # Session Timeouts and Windows Optimizations
        ##############################################################
        #New-Item -ItemType Directory -Force -Path "C:\AVDImage"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/ConfigureSessionTimeoutsV2.ps1" -OutFile "C:\management\ConfigureSessionTimeoutsV2.ps1"
        & "C:\management\ConfigureSessionTimeoutsV2.ps1" -MaxDisconnectionTime 5 -MaxIdleTime 120 -RemoteAppLogoffTimeLimit 15 -fResetBroken "1"
        #Remove-Item -Path "C:\AVDImage" -Recurse -Force

        ##############################################################
        # Session Timeouts and Windows Optimizations
        ##############################################################
        #New-Item -ItemType Directory -Force -Path "C:\AVDImage"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/WindowsOptimization.ps1" -OutFile "C:\management\WindowsOptimization.ps1"
        & "C:\management\WindowsOptimization.ps1" -Optimizations "All"
        #Remove-Item -Path "C:\AVDImage" -Recurse -Force
}
catch {
        Write-Log -Message $_ -Category 'Error'
        throw
}
