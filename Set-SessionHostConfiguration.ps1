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
        #  TimeZone and other settings applied
        ##############################################################
        
        Set-WinUILanguageOverride -Language fi-FI
        Set-WinUserLanguageList fi-FI -Force
        Set-WinSystemLocale fi-FI
        Set-Culture fi-FI
        Set-WinHomeLocation -GeoId 77
        Copy-UserInternationalSettingsToSystem -WelcomeScreen $False -NewUser $True
        tzutil /s "FLE Standard Time"
        Write-Log -Message 'Language, locales, culture, region and timezone configured' -Category 'Info'

        ##############################################################
        #  AVD Golden Image Hardening
        #  - Telemetry (policies)
        #  - Consumer Experiences (policy)
        #  - Geolocation (policies)
        #  - Find My Device (policy)
        #  - Improve handwriting/typing (policies)
        #  - Ads / Advertising ID + Tailored experiences (policies)
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
        Write-Log -Message "Telemetry hardened & DiagTrack disabled" -Category 'Info'

        # -------------------------------
        # 2) CONSUMER EXPERIENCES (policy)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
        Write-Log -Message "Consumer experiences disabled" -Category 'Info'

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
        Write-Log -Message "Geolocation disabled (system + apps)" -Category 'Info'

        # -------------------------------
        # 4) FIND MY DEVICE (policy)
        # -------------------------------
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Force | Out-Null
        # 0 = Off, 1 = On
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Type DWord -Value 0
        Write-Log -Message "Find My Device disabled" -Category 'Info'

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
        Write-Log -Message "Handwriting and typing improvement disabled" -Category 'Info'

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
        Write-Log -Message "Windows Search History disabled" -Category 'Info'

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
        Write-Log -Message "First Sign-In Animation and Privacy Settings Experience disabled" -Category 'Info'
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
        # Session Timeouts
        ##############################################################
        New-Item -ItemType Directory -Force -Path "C:\AVDImage"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/ConfigureSessionTimeoutsV2.ps1" -OutFile "C:\AVDImage\ConfigureSessionTimeoutsV2.ps1"
        & "C:\AVDImage\ConfigureSessionTimeoutsV2.ps1" -MaxDisconnectionTime 5 -MaxIdleTime 120 -RemoteAppLogoffTimeLimit 15 -fResetBroken "1"

        ##############################################################
        # Edge Policies
        ##############################################################

        $edgeReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

        function New-EdgeKey($path) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        }

        function Set-DWord($path, $name, $value) {
        New-EdgeKey $path
        New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null
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
        Write-Log -Message "Applying Edge hardening to $edgeReg" -Category 'Info'

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

        # Disable address-bar editing (does NOT fully prevent navigation)
        Set-DWord $edgeReg 'AddressBarEditingEnabled' 0

        # Session-only cookies (except allowlist)
        Set-DWord $edgeReg 'DefaultCookiesSetting' 4

        # Disable Google Cast
        Set-DWord $edgeReg 'EnableMediaRouter' 0

        <# # --- Optional: Cookie exceptions to persist across exit ---
        if ($SaveCookiesOnExitUrls.Count -gt 0) {
        $saveOnExitKey = Join-Path $edgeReg 'SaveCookiesOnExit'
        Set-ListPolicy -baseKey $saveOnExitKey -items $SaveCookiesOnExitUrls
        } #>

        ##############################################################
        # Windows Optimizations
        ##############################################################
        New-Item -ItemType Directory -Force -Path "C:\AVDImage"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Azure/RDS-Templates/refs/heads/master/CustomImageTemplateScripts/CustomImageTemplateScripts_2024-03-27/WindowsOptimization.ps1" -OutFile "C:\AVDImage\WindowsOptimization.ps1"
        & "C:\AVDImage\WindowsOptimization.ps1" -Optimizations "WindowsMediaPlayer","DefaultUserSettings","Autologgers","Services","NetworkOptimizations","LGPO","DiskCleanup","Edge"        

        ##############################################################
        # File Updater & cleanup (Future use with AzCopy)
        ##############################################################
        <#
        #Issue 27: Copy Config.json for Epic Hyperdrive
        $sourceItem = "C:\AIB\software\Hyperdrive\Epic Hyperdrive Setup 100.2508.0\491Config.json"
        $targetFolder = "C:\Program Files (x86)\Epic\Hyperdrive\Config"
        Copy-Item -Path $sourceItem -Destination $targetFolder -Force

        #Issue 25: Copy FileZilla configuration file
        $sourceItem = "C:\AIB\software\FileZilla\fzdefaults.xml"
        $targetFolder = "C:\Program Files\FileZilla FTP Client"
        Copy-Item -Path $sourceItem -Destination $targetFolder -Force

        # Issue 1
        New-Item -ItemType Directory -Force -Path C:\\Sovellukset\Hyperdrive
        New-Item -ItemType Directory -Force -Path C:\\Sovellukset\tukiportaali

        $sourceFolderHyperdriveBatScript = "C:\\AIB\\software\\LastConfigurations\\Hyperdrive"
        $targetFolderHyperdriveBatScript = "C:\\Sovellukset"
        Copy-Item -Path $sourceFolderHyperdriveBatScript -Destination $targetFolderHyperdriveBatScript -Recurse -Force
        Write-Log -Message "HyperdriveBatScript copied successfully" -Category 'Info'

        $sourceFolderTukiportaali = "C:\\AIB\\software\\LastConfigurations\\tukiportaali"
        $targetFolderTukiportaali = "C:\\Sovellukset"
        Copy-Item -Path $sourceFolderTukiportaali -Destination $targetFolderTukiportaali -Recurse -Force
        Write-Log -Message "Edge-Apotti-tukiportaali copied successfully" -Category 'Info'


<#         # Clean up
        $pathsToClean = "C:\\AIB"
        foreach ($path in $($pathsToClean)) { 
                if (Test-Path $path) { 
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue 
                } 
        } #>

        ##############################################################
        # Fixed pagefile on D: and remove any on C:
        ##############################################################
<#
        Write-Log -Message "Configuring fixed pagefile on D: and removing any on C:..." -Category 'Info'

        # Disable automatic management
        Set-CimInstance -Query "SELECT * FROM Win32_ComputerSystem" `
        -Property @{ AutomaticManagedPagefile = $false }

        # Remove any pagefile entry on C:
        Get-CimInstance -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='C:\\pagefile.sys'" |
        Remove-CimInstance -ErrorAction SilentlyContinue

        # Remove any existing pagefile entry on D:
        Get-CimInstance -Query "SELECT * FROM Win32_PageFileSetting WHERE Name='D:\\pagefile.sys'" |
        Remove-CimInstance -ErrorAction SilentlyContinue

        # Create new fixed-size pagefile on D:
        $initialSizeMB = [uint32]10240
        $maxSizeMB     = [uint32]10240

        New-CimInstance -ClassName Win32_PageFileSetting `
        -Property @{
                Name        = "D:\\pagefile.sys"
                InitialSize = $initialSizeMB
                MaximumSize = $maxSizeMB
        }

        Write-Log -Message "Pagefile created on D: with fixed size $initialSizeMB MB." -Category 'Info'
#>

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
}
catch {
        Write-Log -Message $_ -Category 'Error'
        throw
}
