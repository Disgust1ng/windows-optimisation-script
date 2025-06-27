# Windows Privacy & Performance Optimization Script

# === Bitsum Highest Performance Plan ===
Invoke-WebRequest -Uri "https://bitsum.com/files/bitsum-highest-performance.pow" -OutFile "$env:TEMP\bitsum.pow"
powercfg -import "$env:TEMP\bitsum.pow"
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IdleDisable 1
powercfg.exe /setactive SCHEME_CURRENT

# === Disable Services ===
Stop-Service -Name dps -Force -ErrorAction SilentlyContinue
Set-Service -Name "dps" -StartupType Manual
Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
Set-Service -Name "SysMain" -StartupType Manual

# === Spectre/Meltdown Mitigations Disabled (Performance Boost - Security Tradeoff) ===
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisableMeltdown" -Value 1 -Type DWord

# === Registry Tweaks ===
$regEdits = @(
    # Input Personalization
    "HKCU:\Software\Microsoft\InputPersonalization\RestrictImplicitInkCollection",1,
    "HKCU:\Software\Microsoft\InputPersonalization\RestrictImplicitTextCollection",1,
    "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore\HarvestContacts",0,
    "HKCU:\Software\Microsoft\Personalization\Settings\AcceptedPrivacyPolicy",0,
    "HKLM:\Software\Microsoft\InputPersonalization\RestrictImplicitInkCollection",1,
    "HKLM:\Software\Microsoft\InputPersonalization\RestrictImplicitTextCollection",1,
    "HKLM:\Software\Microsoft\InputPersonalization\TrainedDataStore\HarvestContacts",0,
    "HKLM:\Software\Microsoft\Personalization\Settings\AcceptedPrivacyPolicy",0,

    # Cortana & Search
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Windows Search\CortanaConsent",0,
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Windows Search\CortanaConsent",0,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb",0,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\ConnectedSearchUseWeb",0,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\DisableWebSearch",1,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\DisableWebSearch",1,

    # Speech
    "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Preferences\ModelDownloadAllowed",0,
    "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences\ModelDownloadAllowed",0,
    "HKLM:\SOFTWARE\Policies\Microsoft\Speech\AllowSpeechModelUpdate",0,

    # Feedback/Telemetry/Diagnostics
    "HKCU:\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod",0,
    "HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds",0,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications",1,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications",1,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry",0,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry",0,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableOneSettingsDownloads",1,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableOneSettingsDownloads",1,
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection",1,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection",1,

    # Content Delivery Manager - Disable Suggestions
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SystemPaneSuggestionsEnabled",0,
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SystemPaneSuggestionsEnabled",0,
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338387Enabled",0,
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338387Enabled",0,
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SilentInstalledAppsEnabled",0,
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SilentInstalledAppsEnabled",0
)

for ($i = 0; $i -lt $regEdits.Length; $i += 2) {
    $fullPath = $regEdits[$i]
    $value = $regEdits[$i + 1]
    $split = $fullPath.Split(':')
    $hive = $split[0] + ':'
    $keyName = ($split[1] -split '\\')
    $name = $keyName[-1]
    $path = $hive + ($keyName[0..($keyName.Length - 2)] -join '\')
    try {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
    } catch {
        Write-Warning "❌ Failed to set $name at $path"
    }
}

# === Disable Windows Update UI Elements ===
$WUSettings = @(
    "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings\TrayIconVisibility",0,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetUpdateNotificationLevel",0,
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ExcludeWUDriversInQualityUpdate",1,
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata\PreventDeviceMetadataFromNetwork",1
)

for ($j = 0; $j -lt $WUSettings.Length; $j += 2) {
    $fullPath = $WUSettings[$j]
    $value = $WUSettings[$j + 1]
    $split = $fullPath.Split(':')
    $hive = $split[0] + ':'
    $keyName = ($split[1] -split '\\')
    $name = $keyName[-1]
    $path = $hive + ($keyName[0..($keyName.Length - 2)] -join '\')
    try {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
    } catch {
        Write-Warning "❌ Failed to set $name at $path"
    }
}

Write-Host "✅ Optimization script complete. Reboot recommended."
