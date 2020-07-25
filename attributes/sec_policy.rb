# xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords:
default['security_policy']['access']['1.1.1'] = {
  'CIS_Control' => 'PasswordHistorySize = 24',
}

# xccdf_org.cisecurity.benchmarks_rule_1.1.2_L1_Ensure_Maximum_password_age_is_set_to_60_or_fewer_days_but_not_0:
default['security_policy']['access']['1.1.2'] = {
  'CIS_Control' => 'MaximumPasswordAge = 60',
}

# xccdf_org.cisecurity.benchmarks_rule_1.1.3_L1_Ensure_Minimum_password_age_is_set_to_1_or_more_days:
default['security_policy']['access']['1.1.3'] = {
  'CIS_Control' => 'MinimumPasswordAge = 1',
}

# xccdf_org.cisecurity.benchmarks_rule_1.1.4_L1_Ensure_Minimum_password_length_is_set_to_14_or_more_characters
default['security_policy']['access']['1.1.4'] = {
  'CIS_Control' => 'MinimumPasswordLength = 14',
}

# xccdf_org.cisecurity.benchmarks_rule_1.1.5_L1_Ensure_Password_must_meet_complexity_requirements_is_set_to_Enabled:
default['security_policy']['access']['1.1.5'] = {
  'CIS_Control' => 'PasswordComplexity = 1',
}

# xccdf_org.cisecurity.benchmarks_rule_1.1.6_L1_Ensure_Store_passwords_using_reversible_encryption_is_set_to_Disabled:
default['security_policy']['access']['1.1.6'] = {
  'CIS_Control' => 'ClearTextPassword = 0',
}

# xccdf_org.cisecurity.benchmarks_rule_1.2.1_L1_Ensure_Account_lockout_duration_is_set_to_15_or_more_minutes
default['security_policy']['access']['1.2.1'] = {
  'CIS_Control' => 'LockoutDuration = 15',
}

# xccdf_org.cisecurity.benchmarks_rule_1.2.2_L1_Ensure_Account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0:
default['security_policy']['access']['1.2.2'] = {
  'CIS_Control' => 'LockoutBadCount = 10',
}

# xccdf_org.cisecurity.benchmarks_rule_1.2.3_L1_Ensure_Reset_account_lockout_counter_after_is_set_to_15_or_more_minutes:
default['security_policy']['access']['1.2.3'] = {
  'CIS_Control' => 'ResetLockoutCount = 15',
}

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.1_L1_Ensure_Network_access_Allow_anonymous_SIDName_translation_is_set_to_Disabled
default['security_policy']['access']['2.3.10.1'] = {
  'CIS_Control' => 'LSAAnonymousNameLookup = 1',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One:
default['security_policy']['rights']['Access credential Manager as a trusted caller'] = {
  'CIS_Control' => 'SeTrustedCredManAccessPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Ensure_Access_this_computer_from_the_network:
default['security_policy']['rights']['Access this computer from the network'] = {
  'CIS_Control' => 'SeNetworkLogonRight = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_None:
default['security_policy']['rights']['Act as part of the operating system'] = {
  'CIS_Control' => 'SeTcbPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.4_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE:
default['security_policy']['rights']['Adjust memory quotas for a process'] = {
  'CIS_Control' => 'SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.5_L1_Ensure_Allow_log_on_locally_is_set_to_Administrators_Users:
default['security_policy']['rights']['Allow log on locally'] = {
  'CIS_Control' => 'SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Ensure_Allow_log_on_through_Remote_Desktop_Services_Administrators:
default['security_policy']['rights']['Allow log on through Remote Desktop Services'] = {
  'CIS_Control' => 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators:
default['security_policy']['rights']['Back up files and directories'] = {
  'CIS_Control' => 'SeBackupPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.8_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE:
default['security_policy']['rights']['Change the system time'] = {
  'CIS_Control' => 'SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE_Users:
default['security_policy']['rights']['Change the time zone'] = {
  'CIS_Control' => 'SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Create_a_pagefile_is_set_to_Administrators:
default['security_policy']['rights']['Create a pagefile'] = {
  'CIS_Control' => 'SeCreatePagefilePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Create_a_token_object_is_set_to_No_One:
default['security_policy']['rights']['Create a token object'] = {
  'CIS_Control' => 'SeCreateTokenPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE:
default['security_policy']['rights']['Create global objects'] = {
  'CIS_Control' => 'SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One:
default['security_policy']['rights']['Create permanent shared objects'] = {
  'CIS_Control' => 'SeCreatePermanentPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_symbolic_links_Administrators:
default['security_policy']['rights']['Create symbolic links'] = {
  'CIS_Control' => 'SeCreateSymbolicLinkPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Ensure_Debug_programs_is_set_to_Administrators:
default['security_policy']['rights']['Debug programs'] = {
  'CIS_Control' => 'SeDebugPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Deny_access_to_this_computer_from_the_network_to_include_Guests_Local_account:
default['security_policy']['rights']['Deny access to this computer from the network'] = {
  'CIS_Control' => 'SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.17_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests:
default['security_policy']['rights']['Deny log on as a batch job'] = {
  'CIS_Control' => 'SeDenyBatchLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests:
default['security_policy']['rights']['Deny log on as a service'] = {
  'CIS_Control' => 'SeDenyServiceLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Deny_log_on_locally_to_include_Guests:
default['security_policy']['rights']['Deny log on locally'] = {
  'CIS_Control' => 'SeDenyInteractiveLogonRight = *S-1-5-32-546',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.20_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_is_set_to_Guests_Local_account
default['security_policy']['rights']['Deny log on through Remote Desktop Services'] = {
  'CIS_Control' => 'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation:
default['security_policy']['rights']['Enable computer and user accounts to be trusted for delegation'] = {
  'CIS_Control' => 'SeEnableDelegationPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators:
default['security_policy']['rights']['Force shutdown from a remote system'] = {
  'CIS_Control' => 'SeRemoteShutdownPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE:
default['security_policy']['rights']['Generate security audits'] = {
  'CIS_Control' => 'SeAuditPrivilege = *S-1-5-20,*S-1-5-19',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Impersonate_a_client_after_authentication_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE:
default['security_policy']['rights']['Impersonate a client after authentication'] = {
  'CIS_Control' => 'SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-17',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.25_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators:
default['security_policy']['rights']['Increase scheduling priority'] = {
  'CIS_Control' => 'SeIncreaseBasePriorityPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators:
default['security_policy']['rights']['Load and unload device drivers'] = {
  'CIS_Control' => 'SeLoadDriverPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.27_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One:
default['security_policy']['rights']['Lock pages in memory'] = {
  'CIS_Control' => 'SeLockMemoryPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Ensure_Manage_auditing
default['security_policy']['rights']['Manage auditing and security log'] = {
  'CIS_Control' => 'SeSecurityPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.31_L1_Ensure_Modify_an_object_label_is_set_to_No_One:
default['security_policy']['rights']['Modify an object label'] = {
  'CIS_Control' => 'SeRelabelPrivilege = ',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators:
default['security_policy']['rights']['Modify firmware environment values'] = {
  'CIS_Control' => 'SeSystemEnvironmentPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators:
default['security_policy']['rights']['Perform volume maintenance tasks'] = {
  'CIS_Control' => 'SeManageVolumePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Profile_single_process_is_set_to_Administrators:
default['security_policy']['rights']['Profile single process'] = {
  'CIS_Control' => 'SeProfileSingleProcessPrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICE\\WdiServiceHost_:
default['security_policy']['rights']['Profile system performance'] = {
  'CIS_Control' => 'SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.36_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE_:
default['security_policy']['rights']['Replace a process level token'] = {
  'CIS_Control' => 'SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.37_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators:
default['security_policy']['rights']['Restore files and directories'] = {
  'CIS_Control' => 'SeRestorePrivilege = *S-1-5-32-544',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.38_L1_Ensure_Shut_down_the_system_is_set_to_Administrators_Users:
default['security_policy']['rights']['Shut down the system'] = {
  'CIS_Control' => 'SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545',
}

# xccdf_org.cisecurity.benchmarks_rule_2.2.39_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators:
default['security_policy']['rights']['Take ownership of files or other objects'] = {
  'CIS_Control' => 'SeTakeOwnershipPrivilege = *S-1-5-32-544',
}