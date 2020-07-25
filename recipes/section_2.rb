# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_2
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.2_L1_Ensure_Accounts_Block_Microsoft_accounts_is_set_to_Users_cant_add_or_log_on_with_Microsoft_accounts
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'NoConnectedUser', type: :dword, data: 3 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.4_L1_Ensure_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'LimitBlankPasswordUse', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.1_L1_Ensure_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'SCENoApplyLegacyAuditPolicy', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.2_L1_Ensure_Audit_Shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\LSA' do
  values [{ name: 'CrashOnAuditFail', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.4.1_L1_Ensure_Devices_Allowed_to_format_and_eject_removable_media_is_set_to_Administrators_and_Interactive_Users
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'AllocateDASD', type: :string, data: '2' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.1_L1_Ensure_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'RequireSignOrSeal', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.2_L1_Ensure_Domain_member_Digitally_encrypt_secure_channel_data_when_possible_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'SealSecureChannel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.3_L1_Ensure_Domain_member_Digitally_sign_secure_channel_data_when_possible_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'SignSecureChannel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.4_L1_Ensure_Domain_member_Disable_machine_account_password_changes_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'DisablePasswordChange', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.5_L1_Ensure_Domain_member_Maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'MaximumPasswordAge', type: :dword, data: 30 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.6_L1_Ensure_Domain_member_Require_strong_Windows_2000_or_later_session_key_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'RequireStrongKey', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.1_L1_Ensure_Interactive_logon_Do_not_display_last_user_name_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DontDisplayLastUserName', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.2_L1_Ensure_Interactive_logon_Do_not_require_CTRLALTDEL_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DisableCAD', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.4_L1_Ensure_Interactive_logon_Machine_inactivity_limit_is_set_to_900_or_fewer_seconds_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'InactivityTimeoutSecs', type: :dword, data: 900 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.5_L1_Configure_Interactive_logon_Message_text_for_users_attempting_to_log_on
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LegalNoticeText', type: :string, data: 'WARNING : Only for LAB testing purpose.' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.6_L1_Configure_Interactive_logon_Message_title_for_users_attempting_to_log_on
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LegalNoticeCaption', type: :string, data: 'PJ Infrastructure As Code' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.8_L1_Ensure_Interactive_logon_Prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'PasswordExpiryWarning', type: :dword, data: 7 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.9_L1_Ensure_Interactive_logon_Smart_card_removal_behavior_is_set_to_Lock_Workstation_or_higher
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'ScRemoveOption', type: :string, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.1_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'RequireSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.2_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_if_server_agrees_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'EnableSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.3_L1_Ensure_Microsoft_network_client_Send_unencrypted_password_to_third-party_SMB_servers_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'EnablePlainTextPassword', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.1_L1_Ensure_Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'AutoDisconnect', type: :dword, data: 15 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.2_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'RequireSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.3_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_if_client_agrees_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'EnableSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.4_L1_Ensure_Microsoft_network_server_Disconnect_clients_when_logon_hours_expire_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'EnableForcedLogOff', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.5_L1_Ensure_Microsoft_network_server_Server_SPN_target_name_validation_level_is_set_to_Accept_if_provided_by_client_or_higher_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
  values [{ name: 'SMBServerNameHardeningLevel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.1_L1_Ensure_Network_access_Allow_anonymous_SIDName_translation_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'TurnOffAnonymousBlock', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.2_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'RestrictAnonymousSAM', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.3_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'RestrictAnonymous', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.4_L1_Ensure_Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'disabledomaincreds', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.5_L1_Ensure_Network_access_Let_Everyone_permissions_apply_to_anonymous_users_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'EveryoneIncludesAnonymous', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.6_L1_Ensure_Network_access_Named_Pipes_that_can_be_accessed_anonymously_is_set_to_None
execute 'registry_key[2.3.10.6]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\NullSessionPipes.lock') }
  notifies :create, 'file[C:\cis-level1-harden\NullSessionPipes.lock]', :immediately
end

file 'C:\cis-level1-harden\NullSessionPipes.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.7_L1_Ensure_Network_access_Remotely_accessible_registry_paths
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths' do
  values [{ name: 'Machine', type: :multi_string,
    data: ['System\CurrentControlSet\Control\ProductOptions',
           'System\CurrentControlSet\Control\Server Applications',
           'Software\Microsoft\Windows NT\CurrentVersion']
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.8_L1_Ensure_Network_access_Remotely_accessible_registry_paths_and_sub-paths
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths' do
  values [{ name: 'Machine', type: :multi_string,
    data: ['System\CurrentControlSet\Control\Print\Printers',
           'System\CurrentControlSet\Services\Eventlog',
           'Software\Microsoft\OLAP Server',
           'Software\Microsoft\Windows NT\CurrentVersion\Print',
           'Software\Microsoft\Windows NT\CurrentVersion\Windows',
           'System\CurrentControlSet\Control\ContentIndex',
           'System\CurrentControlSet\Control\Terminal Server',
           'System\CurrentControlSet\Control\Terminal Server\UserConfig',
           'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration',
           'Software\Microsoft\Windows NT\CurrentVersion\Perflib',
           'System\CurrentControlSet\Services\SysmonLog']
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.9_L1_Ensure_Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'restrictnullsessaccess', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.10_L1_Ensure_Network_access_Shares_that_can_be_accessed_anonymously_is_set_to_None
execute 'registry_key[2.3.10.10]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\NullSessionShares.lock') }
  notifies :create, 'file[C:\cis-level1-harden\NullSessionShares.lock]', :immediately
end

file 'C:\cis-level1-harden\NullSessionShares.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.11_L1_Ensure_Network_access_Sharing_and_security_model_for_local_accounts_is_set_to_Classic_-_local_users_authenticate_as_themselves
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'ForceGuest', type: :dword, data: 0 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.1_L1_Ensure_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'UseMachineId', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.2_L1_Ensure_Network_security_Allow_LocalSystem_NULL_session_fallback_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'AllowNullSessionFallback', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.3_L1_Ensure_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u' do
  values [{ name: 'AllowOnlineID', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.4_L1_Ensure_Network_security_Configure_encryption_types_allowed_for_Kerberos_is_set_to_AES128_HMAC_SHA1_AES256_HMAC_SHA1_Future_encryption_types
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' do
  values [{ name: 'SupportedEncryptionTypes', type: :dword, data: 2147483644 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.5_L1_Ensure_Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'NoLMHash', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1_Ensure_Network_security_LAN_Manager_authentication_level_is_set_to_Send_NTLMv2_response_only._Refuse_LM__NTLM
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'LmCompatibilityLevel', type: :dword, data: 5 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.8_L1_Ensure_Network_security_LDAP_client_signing_requirements_is_set_to_Negotiate_signing_or_higher
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP' do
  values [{ name: 'LDAPClientIntegrity', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.9_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'NTLMMinClientSec', type: :dword, data: 537395200 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.10_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'NTLMMinServerSec', type: :dword, data: 537395200 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.1_L1_Ensure_System_objects_Require_case_insensitivity_for_non-Windows_subsystems_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel' do
  values [{ name: 'ObCaseInsensitive', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.2_L1_Ensure_System_objects_Strengthen_default_permissions_of_internal_system_objects_e.g._Symbolic_Links_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager' do
  values [{ name: 'ProtectionMode', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.1_L1_Ensure_User_Account_Control_Admin_Approval_Mode_for_the_Built-in_Administrator_account_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'FilterAdministratorToken', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.2_L1_Ensure_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableUIADesktopToggle', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.3_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_is_set_to_Prompt_for_consent_on_the_secure_desktop
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'ConsentPromptBehaviorAdmin', type: :dword, data: 2 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.4_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_is_set_to_Automatically_deny_elevation_requests
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'ConsentPromptBehaviorUser', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.5_L1_Ensure_User_Account_Control_Detect_application_installations_and_prompt_for_elevation_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableInstallerDetection', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.6_L1_Ensure_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableSecureUIAPaths', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.7_L1_Ensure_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableLUA', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.8_L1_Ensure_User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'PromptOnSecureDesktop', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.9_L1_Ensure_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per-user_locations_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableVirtualization', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled_MS_only
powershell_script 'Disable guest account' do
  code 'net user guest /active:no'
  action :run
  only_if "(net user guest | Select-String -Pattern 'Account active.*Yes') -ne $null"
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account
powershell_script 'Rename Administrator Account' do
  code <<-EOH
  Rename-LocalUser -Name "Administrator" -NewName "win10-admin"
  EOH
  only_if '((Get-LocalUser -Name "Administrator").Name -eq "administrator")'
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.6_L1_Configure_Accounts_Rename_guest_account
powershell_script 'Rename Guest Account' do
  code <<-EOH
  Rename-LocalUser -Name "Guest" -NewName "Guuest"
  EOH
  only_if '((Get-LocalUser -Name "Guest").Name -eq "Guest")'
end
