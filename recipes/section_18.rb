# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_18
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled
# xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization' do
  values [{ name: 'NoLockScreenCamera', type: :dword, data: 1 }, { name: 'NoLockScreenSlideshow', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_input_personalization_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\InputPersonalization' do
  values [{ name: 'AllowInputPersonalization', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_input_personalization_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\InputPersonalization' do
  values [{ name: 'AllowInputPersonalization', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only
windows_package 'LAPS_AdmPwd_GPO_Extension' do
  source 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi'
  installer_type :custom
  options '/quiet'
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PwdExpirationProtectionEnabled', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'AdmPwdEnabled', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordComplexity', type: :dword, data: 4 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordLength', type: :dword, data: 15 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordAgeDays', type: :dword, data: 30 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'AutoAdminLogon', type: :string, data: '0' }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\System\\CurrentControlSet\\Services\\Tcpip\\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters' do
  values [{ name: 'EnableICMPRedirect', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.7_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters' do
  values [{ name: 'nonamereleaseondemand', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.9_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager' do
  values [{ name: 'SafeDllSearchMode', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.10_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'ScreenSaverGracePeriod', type: :dword, data: 5 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.13_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security' do
  values [{ name: 'WarningLevel', type: :dword, data: 90 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.7.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation' do
  values [{ name: 'AllowInsecureGuestAuth', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.10.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' do
  values [{ name: 'NC_AllowNetBridge_NLA', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.10.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' do
  values [{ name: 'NC_StdDomainUserSetLocation', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.13.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths' do
  values [{ name: '\\\\*\\SYSVOL', type: :string, data: 'RequireMutualAuthentication=1, RequireIntegrity=1' }, { name: '\\\\*\\NETLOGON', type: :string, data: 'RequireMutualAuthentication=1, RequireIntegrity=1' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.20.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy' do
  values [{ name: 'fMinimizeConnections', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.20.2_L1_Ensure_Prohibit_connection_to_non-domain_networks_when_connected_to_domain_authenticated_network_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy' do
  values [{ name: 'fBlockNonDomain', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.22.2.1_L1_Ensure_Allow_Windows_to_automatically_connect_to_suggested_open_hotspots_to_networks_shared_by_contacts_and_to_hotspots_offering_paid_services_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config' do
  values [{ name: 'AutoConnectAllowedOEM', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LocalAccountTokenFilterPolicy', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.6.2_L1_Ensure_WDigest_Authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' do
  values [{ name: 'UseLogonCredential', type: :string, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.2.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' do
  values [{ name: 'ProcessCreationIncludeCmdLine_Enabled', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.11.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch' do
  values [{ name: 'DriverLoadPolicy', type: :dword, data: 3 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.18.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoBackgroundPolicy', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.18.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoGPOListChanges', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.18.4_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DisableBkGndGroupPolicy', type: :dword, data: 0 }]
  action :delete
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.24.1_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DontDisplayNetworkSelectionUI', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.24.2_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DontEnumerateConnectedUsers', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.24.3_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'EnumerateLocalUsers', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.24.4_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DisableLockScreenAppNotifications', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.24.5_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'AllowDomainPINLogon', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\MitigationOptions' do
  values [{ name: 'MitigationOptions_FontBocking', type: :string, data: '1000000000000' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.3_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'DCSettingIndex', type: :string, data: '1' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'ACSettingIndex', type: :string, data: '1' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.30.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fAllowUnsolicited', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.30.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fAllowToGetHelp', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.31.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc' do
  values [{ name: 'EnableAuthEpResolution', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.31.2_L1_Ensure_Restrict_Unauthenticated_RPC_clients_is_set_to_Enabled_Authenticated
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc' do
  values [{ name: 'RestrictRemoteClients', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'MSAOptional', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoAutoplayfornonVolume', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'NoAutorun', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'NoDriveTypeAutoRun', type: :dword, data: 255 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Use_enhanced_anti-spoofing_when_available_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Biometrics\\FacialFeatures' do
  values [{ name: 'EnhancedAntiSpoofing', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.12.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CloudContent' do
  values [{ name: 'DisableWindowsConsumerFeatures', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.13.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI' do
  values [{ name: 'DisablePasswordReveal', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.13.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI' do
  values [{ name: 'EnumerateAdministrators', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection' do
  values [{ name: 'AllowTelemetry', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.2_L1_Ensure_Disable_pre-release_features_or_settings_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds' do
  values [{ name: 'EnableConfigFlighting', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.3_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' do
  values [{ name: 'DoNotShowFeedbackNotifications', type: :dword, data: 1
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds' do
  values [{ name: 'AllowBuildPreview', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Download_Mode_is_set_to_Enabled_None_or_LAN_or_Group_or_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization' do
  values [{ name: 'DODownloadMode', type: :dword, data: 2 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.22.2_L1_Ensure_Default_Action_and_Mitigation_Settings_is_set_to_Enabled_plus_subsettings
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{ name: 'AntiDetours', type: :dword, data: 1 },
          { name: 'BannedFunctions', type: :dword, data: 1 },
          { name: 'DeepHooks', type: :dword, data: 1 },
          { name: 'ExploitAction', type: :dword, data: 2 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{ name: 'MaxSize', type: :dword, data: 196608 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.28.2_L1_Ensure_Configure_Windows_SmartScreen_is_set_to_Enabled_Require_approval_from_an_administrator_before_running_downloaded_unknown_software
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'EnableSmartScreen', type: :dword, data: 2 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.28.3_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoDataExecutionPrevention', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.28.4_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoHeapTerminationOnCorruption', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.28.5_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'PreXPSP2ShellProtocolBehavior', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.31.1_L1_Ensure_Prevent_the_computer_from_joining_a_homegroup_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup' do
  values [{ name: 'DisableHomeGroup', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.38.1_L1_Ensure_Configure_Cookies_is_set_to_Enabled_Block_only_3rd-party_cookies._or_higher
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main' do
  values [{ name: 'Cookies', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.38.4_L1_Ensure_Dont_allow_WebRTC_to_share_the_LocalHost_IP_address_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main' do
  values [{ name: 'HideLocalHostIP', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.38.5_L1_Ensure_Turn_off_address_bar_search_suggestions_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\SearchScopes' do
  values [{ name: 'ShowSearchSuggestionsGlobal', type: :dword, data: 0 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.38.7_L1_Ensure_Turn_off_Password_Manager_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main' do
  values [{ name: 'FormSuggest Passwords', type: :string, data: 'no' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.38.9_L1_Ensure_Turn_off_the_SmartScreen_Filter_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter' do
  values [{ name: 'EnabledV9', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.43.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive' do
  values [{ name: 'DisableFileSyncNGSC', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'DisablePasswordSaving', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fDisableCdm', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fPromptForPassword', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fEncryptRPCTraffic', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'MinEncryptionLevel', type: :dword, data: 3 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'PerSessionTempDir', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'DeleteTempDirsOnExit', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.49.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds' do
  values [{ name: 'DisableEnclosureDownload', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.50.2_L1_Ensure_Allow_Cortana_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' do
  values [{ name: 'AllowCortana', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.50.3_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' do
  values [{ name: 'AllowIndexingEncryptedStoresOrItems', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.50.4_L1_Ensure_Allow_search_and_Cortana_to_use_location_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' do
  values [{ name: 'AllowSearchToUseLocation', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.2_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore' do
  values [{ name: 'AutoDownload', type: :dword, data: 4 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore' do
  values [{ name: 'DisableOSUpgrade', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.68.1_L1_Ensure_Enables_or_disables_Windows_Game_Recording_and_Broadcasting_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\\Windows\\GameDVR' do
  values [{ name: 'AllowGameDVR', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.69.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' do
  values [{ name: 'EnableUserControl', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.69.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' do
  values [{ name: 'AlwaysInstallElevated', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.70.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system' do
  values [{ name: 'DisableAutomaticRestartSignOn', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.79.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' do
  values [{ name: 'EnableScriptBlockLogging', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.79.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' do
  values [{ name: 'EnableTranscripting', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowBasic', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowDigest', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'AllowBasic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.3_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'DisableRunAs', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.1_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'NoAutoUpdate', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.2_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'ScheduledInstallDay', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.3_L1_Ensure_Defer_Upgrades_and_Updates_is_set_to_Enabled_8_months_0_weeks
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' do
  values [{ name: 'DeferUpgrade', type: :dword, data: 1 },
          { name: 'DeferUpgradePeriod', type: :dword, data: 8 },
          { name: 'DeferUpdatePeriod', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'NoAutoRebootWithLoggedOnUsers', type: :dword, data: 0 }]
  recursive true
  action :create
end
