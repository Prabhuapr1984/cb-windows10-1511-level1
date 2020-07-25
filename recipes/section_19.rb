# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_19
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_19.1.3.1_L1_Ensure_Enable_screen_saver_is_set_to_Enabled
powershell_script 'Enable_screen_saver' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"); New-Item $regpath -force | New-ItemProperty -Name 'ScreenSaveActive' -Value '1' -PropertyType string -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -name "ScreenSaveActive") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.1.3.2_L1_Ensure_Force_specific_screen_saver_Screen_saver_executable_name_is_set_to_Enabled_scrnsave.scr
powershell_script 'Force_specific_screen_saver' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"); New-ItemProperty -path $regpath -Name 'SCRNSAVE.EXE' -Value 'scrnsave.scr' -PropertyType string -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -name "SCRNSAVE.EXE") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.1.3.3_L1_Ensure_Password_protect_the_screen_saver_is_set_to_Enabled
powershell_script 'protect_the_screen_saver' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"); New-ItemProperty -path $regpath -Name 'ScreenSaverIsSecure' -Value '1' -PropertyType string -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -name "ScreenSaverIsSecure") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.1.3.4_L1_Ensure_Screen_saver_timeout_is_set_to_Enabled_900_seconds_or_fewer_but_not_0
powershell_script 'Screen_saver_timeout' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop"); New-ItemProperty -path $regpath -Name 'ScreenSaveTimeOut' -Value '900' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" -name "ScreenSaveTimeOut") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.5.1.1_L1_Ensure_Turn_off_toast_notifications_on_the_lock_screen_is_set_to_Enabled
powershell_script 'Turn_off_toast_notifications' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications"); New-Item $regpath -force |New-ItemProperty -Name 'NoToastApplicationNotificationOnLockScreen' -Value '1' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" -name "NoToastApplicationNotificationOnLockScreen") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.7.4.1_L1_Ensure_Do_not_preserve_zone_information_in_file_attachments_is_set_to_Disabled
powershell_script 'zone_information' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"); New-Item $regpath -force | New-ItemProperty -Name 'SaveZoneInformation' -Value '2' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" -name "SaveZoneInformation") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.7.4.2_L1_Ensure_Notify_antivirus_programs_when_opening_attachments_is_set_to_Enabled
powershell_script 'Notify_antivirus_programs' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"); New-ItemProperty -path $regpath -Name 'ScanWithAntiVirus' -Value '3' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" -name "ScanWithAntiVirus") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.7.7.1_L1_Ensure_Configure_Windows_spotlight_on_lock_screen_is_set_to_Disabled:
powershell_script 'Windows_spotlight_on_lock' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\CloudContent"); New-ItemProperty -path $regpath -Name 'ConfigureWindowsSpotlight' -Value '2' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\CloudContent" -name "ConfigureWindowsSpotlight") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.7.25.1_L1_Ensure_Prevent_users_from_sharing_files_within_their_profile._is_set_to_Enabled
powershell_script 'Prevent_users_from_sharing_files' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"); New-Item $regpath -force |New-ItemProperty -Name 'NoInplaceSharing' -Value '1' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -name "NoInplaceSharing") -eq $null'
end

# xccdf_org.cisecurity.benchmarks_rule_19.7.37.1_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled
powershell_script 'Always_install_with_elevated' do
  code <<-EOH
    $sid=((New-Object System.Security.Principal.NTAccount('local-admin')).Translate([System.Security.Principal.SecurityIdentifier]).Value); ($regpath = "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Installer"); New-Item $regpath -force |New-ItemProperty -Name 'AlwaysInstallElevated' -Value '0' -PropertyType dword -Force |Out-Null
  EOH
  only_if '$sid=((New-Object System.Security.Principal.NTAccount("local-admin")).Translate([System.Security.Principal.SecurityIdentifier]).Value); (Get-ItemProperty "Registry::HKEY_USERS\\$sid\\Software\\Policies\\Microsoft\\Windows\\Installer" -name "AlwaysInstallElevated") -eq $null'
end
