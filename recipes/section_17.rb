# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_17
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_17.1.1_L1_Ensure_Audit_Credential_Validation_is_set_to_Success_and_Failure:
audit_policy 'Audit Credential Validation - Success, Failure' do
  subcategory 'Credential Validation'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.2.1_L1_Ensure_Audit_Application_Group_Management_is_set_to_Success_and_Failure:
audit_policy 'Audit Application Group Management - No Auditing' do
  subcategory 'Application Group Management'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.2.2_L1_Ensure_Audit_Computer_Account_Management_is_set_to_Success_and_Failure:
audit_policy 'Audit Computer Account Management - Success, Failure' do
  subcategory 'Computer Account Management'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.2.4_L1_Ensure_Audit_Other_Account_Management_Events_is_set_to_Success_and_Failure:
audit_policy 'Audit Other Account Management Events - Success, Failure' do
  subcategory 'Other Account Management Events'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.2.5_L1_Ensure_Audit_Security_Group_Management_is_set_to_Success_and_Failure:
audit_policy 'Audit Security Group Management - Success, Failure' do
  subcategory 'Security Group Management'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.2.6_L1_Ensure_Audit_User_Account_Management_is_set_to_Success_and_Failure:
audit_policy 'Audit User Account Management - Success, Failure' do
  subcategory 'User Account Management'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success:
audit_policy 'Detailed Tracking - Success' do
  subcategory 'Plug and Play Events'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.3.2_L1_Ensure_Audit_Process_Creation_is_set_to_Success:
audit_policy 'Audit Process Creation - Success' do
  subcategory 'Process Creation'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.1_L1_Ensure_Audit_Account_Lockout_is_set_to_Success_and_Failure:
audit_policy 'Audit Account Lockout - Success, Failure' do
  subcategory 'Account Lockout'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.2_L1_Ensure_Audit_Group_Membership_is_set_to_Success:
audit_policy 'Audit Group Membership - Success' do
  subcategory 'Group Membership'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.3_L1_Ensure_Audit_Logoff_is_set_to_Success:
audit_policy 'Audit Logoff - Success' do
  subcategory 'Logoff'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.4_L1_Ensure_Audit_Logon_is_set_to_Success_and_Failure:
audit_policy 'Audit Logon - Success, Failure' do
  subcategory 'Logon'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.5_L1_Ensure_Audit_Other_LogonLogoff_Events_is_set_to_Success_and_Failure:
audit_policy 'Audit Other Logon/Logoff Events - Success, Failure' do
  subcategory 'Other Logon/Logoff Events'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.5.6_L1_Ensure_Audit_Special_Logon_is_set_to_Success:
audit_policy 'Audit Special Logon - Success' do
  subcategory 'Special Logon'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.6.1_L1_Ensure_Audit_Removable_Storage_is_set_to_Success_and_Failure
audit_policy 'Audit Removable Storage - Success, Failure' do
  subcategory 'Removable Storage'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.7.1_L1_Ensure_Audit_Audit_Policy_Change_is_set_to_Success_and_Failure:
audit_policy 'Audit Audit Policy Change - Success, Failure' do
  subcategory 'Audit Policy Change'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.7.2_L1_Ensure_Audit_Authentication_Policy_Change_is_set_to_Success:
audit_policy 'Audit Authentication Policy Change - Success' do
  subcategory 'Authentication Policy Change'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.8.1_L1_Ensure_Audit_Sensitive_Privilege_Use_is_set_to_Success_and_Failure:
audit_policy 'Audit Sensitive Privilege - Success and Failure' do
  subcategory 'Sensitive Privilege Use'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.9.1_L1_Ensure_Audit_IPsec_Driver_is_set_to_Success_and_Failure:
audit_policy 'Audit IPsec Driver - Success, Failure' do
  subcategory 'IPsec Driver'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.9.2_L1_Ensure_Audit_Other_System_Events_is_set_to_Success_and_Failure:
audit_policy 'Audit Other System Events - Success and Failure' do
  subcategory 'Other System Events'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.9.3_L1_Ensure_Audit_Security_State_Change_is_set_to_Success:
audit_policy 'Audit Security State Change - Success' do
  subcategory 'Security State Change'
  flag 'Success'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.9.4_L1_Ensure_Audit_Security_System_Extension_is_set_to_Success_and_Failure:
audit_policy 'Audit Security System Extension - Success and Failure' do
  subcategory 'Security System Extension'
  flag 'Success and Failure'
  action :set
end

# xccdf_org.cisecurity.benchmarks_rule_17.9.5_L1_Ensure_Audit_System_Integrity_is_set_to_Success_and_Failure:
audit_policy 'Audit System Integrity - Success and Failure' do
  subcategory 'System Integrity'
  flag 'Success and Failure'
  action :set
end
