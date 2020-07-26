# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_2_dsc
#
# Copyright:: 2019, The Authors, All Rights Reserved.

class ::Chef::Resource
  include ::Windows10Hardening::Helpers
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One
dsc_resource 'Limit access to credential Manager as a trusted caller' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Access_Credential_Manager_as_a_trusted_caller'
  property :identity, ['']
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Access_this_computer_from_the_network__is_set_to_Administrators_Authenticated_Users_MS_only
dsc_resource 'Limit access to this computer from the network' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Access_this_computer_from_the_network'
  property :identity, valid_users_groups(['Authenticated Users', 'Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.4_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_No_One
dsc_resource 'Limit users who can act as part of the operating system' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Act_as_part_of_the_operating_system'
  property :identity, valid_users_groups([''])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE
dsc_resource 'Limit who can adjust memory quotas for a process' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Adjust_memory_quotas_for_a_process'
  property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Ensure_Allow_log_on_locally_is_set_to_Administrators
dsc_resource 'Limit who can Allow_log_on_locally' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Allow_log_on_locally'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Allow_log_on_through_Remote_Desktop_Services_is_set_to_Administrators_Remote_Desktop_Users_MS_only
dsc_resource 'Limit who can log on through remote desktop services' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Allow_log_on_through_Remote_Desktop_Services'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators
dsc_resource 'Limit who can backup files and directories' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Back_up_files_and_directories'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE
dsc_resource 'Limit who can change the system time' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Change_the_system_time'
  property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE
dsc_resource 'Limit who can change the time zone' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Change_the_time_zone'
  property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_a_pagefile_is_set_to_Administrators
dsc_resource 'Limit who can create a pagefile' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Create_a_pagefile'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_a_token_object_is_set_to_No_One
dsc_resource 'Limit Create_a_token_object' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Create_a_token_object'
  property :identity, valid_users_groups([''])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE
dsc_resource 'Limit who can create a token object' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Create_global_objects'
  property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One
dsc_resource 'Limit who can create permanent shared objects' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Create_permanent_shared_objects'
  property :identity, ['']
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Create_symbolic_links_is_set_to_Administrators_NT_VIRTUAL_MACHINEVirtual_Machines_MS_only
dsc_resource 'Create symbolic links' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Create_symbolic_links'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Debug_programs_is_set_to_Administrators
dsc_resource 'Limit who can debug programs' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Debug_programs'
  property :identity, valid_users_groups(%w(Administrators))
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Deny_access_to_this_computer_from_the_network_is_set_to_Guests_Local_account_and_member_of_Administrators_group_MS_only
dsc_resource 'Deny access to this computer from the network' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Deny_access_to_this_computer_from_the_network'
  property :identity, valid_users_groups(%w(Guests Administrators))
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests
dsc_resource 'Deny log on as a batch job' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Deny_log_on_as_a_batch_job'
  property :identity, valid_users_groups(['Guests'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests
dsc_resource 'Deny log on as a service' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Deny_log_on_as_a_service'
  property :identity, valid_users_groups(['Guests'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Deny_log_on_locally_to_include_Guests
dsc_resource 'Deny log on locally' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Deny_log_on_locally'
  property :identity, valid_users_groups(['Guests'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_is_set_to_Guests_Local_account_MS_only
dsc_resource 'Deny log on through Remote Desktop Services' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Deny_log_on_through_Remote_Desktop_Services'
  property :identity, valid_users_groups(['Guests', 'Local account'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.28_L1_Ensure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation_is_set_to_No_One_MS_only
dsc_resource 'Enable computer and user accounts to be trusted for delegation' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
  property :identity, ['']
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.29_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators
dsc_resource 'Limit who can force shutdown from a remote system' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Force_shutdown_from_a_remote_system'
  property :identity, valid_users_groups(%w(Administrators))
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE
dsc_resource 'Limit who can generate security audits' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Generate_security_audits'
  property :identity, valid_users_groups(['LOCAL SERVICE', 'NETWORK SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Impersonate_a_client_after_authentication_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE_and_when_the_Web_Server_IIS_Role_with_Web_Services_Role_Service_is_installed_IIS_IUSRS_MS_only
dsc_resource 'Limit who can impersonate a client after authentication' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Impersonate_a_client_after_authentication'
  property :identity, valid_users_groups(['Administrators', 'SERVICE', 'LOCAL SERVICE', 'NETWORK SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators
dsc_resource 'Limit who can increase scheduling priority' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Increase_scheduling_priority'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators
dsc_resource 'Limit who can load and unload device drivers' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Load_and_unload_device_drivers'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One
dsc_resource 'Limit who can lock pages in memory' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Lock_pages_in_memory'
  property :identity, ['']
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.38_L1_Ensure_Manage_auditing_and_security_log_is_set_to_Administrators_MS_only
dsc_resource 'Limit who can manage auditing and security log' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Manage_auditing_and_security_log'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.39_L1_Ensure_Modify_an_object_label_is_set_to_No_One
dsc_resource 'Limit who can modify an object label' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Modify_an_object_label'
  property :identity, ['']
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.40_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators
dsc_resource 'Limit who can modify firmware environment values' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Modify_firmware_environment_values'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.41_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators
dsc_resource 'Limit who can perform volume maintenance tasks' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Perform_volume_maintenance_tasks'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.42_L1_Ensure_Profile_single_process_is_set_to_Administrators
dsc_resource 'Limit who can profile single process' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Profile_single_process'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.43_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICEWdiServiceHost
dsc_script 'Limit who can profile system performance' do
  imports 'SecurityPolicyDsc'
  code <<-EOH
       UserRightsAssignment AssignShutdownPrivilegesToAdmins
        {
            Policy   = "Profile_system_performance"
            Identity = "Administrators", "NT SERVICE\\WdiServiceHost"
            Force    = $true
        }
EOH
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.44_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE
dsc_resource 'Limit who can replace a process level token' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Replace_a_process_level_token'
  property :identity, valid_users_groups(['LOCAL SERVICE', 'NETWORK SERVICE'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.45_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators
dsc_resource 'Limit who can Restore_files_and_directories' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Restore_files_and_directories'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.46_L1_Ensure_Shut_down_the_system_is_set_to_Administrators
dsc_resource 'Limit who can shut down the system' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Shut_down_the_system'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.2.48_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators
dsc_resource 'Limit who can take ownership of files or other objects' do
  module_name 'SecurityPolicyDsc'
  property :policy, 'Take_ownership_of_files_or_other_objects'
  property :identity, valid_users_groups(['Administrators'])
  property :force, true
  resource :UserRightsAssignment
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account
powershell_script 'Rename Administrator Account' do
  code <<-EOH
  Rename-LocalUser -Name "Administrator" -NewName "local-admin"
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
