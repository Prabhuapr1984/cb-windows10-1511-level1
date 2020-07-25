# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_1
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# create directory to download the modules
directory 'C:\\TEMP\\Download' do
  action :create
  recursive true
end

# Copy the modules zip to temp directory
remote_directory 'C:/Temp' do
  source 'SecurityPolicyDsc' # <-- this is your directory in files/default/local_directory
  action :create
  recursive true
end

# Extract the modules to powershell module directory
powershell_script 'Unzip SecurityPolicyDSC resources to PowerShell Module directory' do
  code <<-EOH
      [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
      [System.IO.Compression.ZipFile]::ExtractToDirectory("C:/Temp/SecurityPolicyDsc.zip", "#{ENV['PROGRAMW6432']}\\WindowsPowerShell\\Modules")
  EOH
  only_if "!(Test-Path -path '#{ENV['PROGRAMW6432']}\\WindowsPowerShell\\Modules\\SecurityPolicyDsc')"
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords
dsc_resource 'Enforce Password History' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :enforce_password_history, 24
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.2.2_L1_Ensure_Account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0
dsc_resource 'Account lockout threshold' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :Account_lockout_threshold, 5
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.2_L1_Ensure_Maximum_password_age_is_set_to_60_or_fewer_days_but_not_0
dsc_resource 'Maximum Password Age' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :maximum_password_age, 60
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.3_L1_Ensure_Minimum_password_age_is_set_to_1_or_more_days
dsc_resource 'Minimum Password Age' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :minimum_password_age, 1
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.4_L1_Ensure_Minimum_password_length_is_set_to_14_or_more_characters
dsc_resource 'Minimum Password Length' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :minimum_password_length, 14
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.5_L1_Ensure_Password_must_meet_complexity_requirements_is_set_to_Enabled
dsc_resource 'Enable Password Complexity' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :password_must_meet_complexity_requirements, 'Enabled'
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.1.6_L1_Ensure_Store_passwords_using_reversible_encryption_is_set_to_Disabled
dsc_resource 'Disabled Reversible Encryption' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :store_passwords_using_reversible_encryption, 'Disabled'
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.2.1_L1_Ensure_Account_lockout_duration_is_set_to_15_or_more_minutes
dsc_resource 'Account Lockout Duration' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :account_lockout_duration, 30
  resource :AccountPolicy
end

# xccdf_org.cisecurity.benchmarks_rule_1.2.3_L1_Ensure_Reset_account_lockout_counter_after_is_set_to_15_or_more_minutes
dsc_resource 'Reset Account Lockout Duration' do
  module_name 'SecurityPolicyDsc'
  property :name, 'PasswordPolicies'
  property :reset_account_lockout_counter_after, 15
  resource :AccountPolicy
end
