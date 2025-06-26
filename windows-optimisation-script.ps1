    #Install and import bitsum highest performance power plan
Invoke-WebRequest -Uri "https://bitsum.com/files/bitsum-highest-performance.pow" -OutFile "$env:TEMP\bitsum.pow"
powercfg -import "$env:TEMP\bitsum.pow"

    #Disable processor parking for selected power profile
powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR IdleDisable 1
powercfg.exe /setactive SCHEME_CURRENT

    #Disable dps
Stop-Service -Name dps
Set-Service -Name "dps" -StartupType Manual

    #Disable SysMain
Stop-Service -Name SysMain
Set-Service -Name "SysMain" -StartupType Manual

    #Enable Threaded DPCs
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel" `
  -Name "ThreadDpcEnable" -Value 0 -Type DWord

  # Spectre/Meltdown Disable
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
  -Name "FeatureSettingsOverride" -Type DWord -Value 3

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
  -Name "FeatureSettingsOverrideMask" -Type DWord -Value 3

# Optional: DisableMeltdown toggle
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
  -Name "DisableMeltdown" -Type DWord -Value 1

# Disable Superfetch (SysMain)
Stop-Service -Name "SysMain" -Force
Set-Service -Name "SysMain" -StartupType Disabled

