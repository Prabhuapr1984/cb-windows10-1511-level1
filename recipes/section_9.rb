# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: section_9
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_9.1.x_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile' do
  values [{ name: 'EnableFirewall', type: :dword, data: 1 },
          { name: 'DefaultInboundAction', type: :dword, data: 1 },
          { name: 'DefaultOutboundAction', type: :dword, data: 0 },
          { name: 'AllowLocalPolicyMerge', type: :dword, data: 1 },
          { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 },
          { name: 'DisableNotifications', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_9.1.x_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging' do
  values [{ name: 'LogFilePath', type: :string, data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log' },
          { name: 'LogFileSize', type: :dword, data: 16384 },
          { name: 'LogDroppedPackets', type: :dword, data: 1 },
          { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_9.2.x_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile' do
  values [{ name: 'EnableFirewall', type: :dword, data: 1 },
          { name: 'DefaultInboundAction', type: :dword, data: 1 },
          { name: 'DefaultOutboundAction', type: :dword, data: 0 },
          { name: 'AllowLocalPolicyMerge', type: :dword, data: 1 },
          { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 1 },
          { name: 'DisableNotifications', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_9.2.x_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging' do
  values [{ name: 'LogFilePath', type: :string, data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log' },
          { name: 'LogFileSize', type: :dword, data: 16384 },
          { name: 'LogDroppedPackets', type: :dword, data: 1 },
          { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_9.3.x_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile' do
  values [{ name: 'EnableFirewall', type: :dword, data: 1 },
          { name: 'DefaultInboundAction', type: :dword, data: 1 },
          { name: 'DefaultOutboundAction', type: :dword, data: 0 },
          { name: 'AllowLocalPolicyMerge', type: :dword, data: 0 },
          { name: 'AllowLocalIPsecPolicyMerge', type: :dword, data: 0 },
          { name: 'DisableNotifications', type: :dword, data: 0 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_9.3.x_L1_Ensure_Windows_Firewall_Public_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallpublicfw.log
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging' do
  values [{ name: 'LogFilePath', type: :string, data: '%systemroot%\\system32\\logfiles\\firewall\\publicfw.log' },
          { name: 'LogFileSize', type: :dword, data: 16384 },
          { name: 'LogDroppedPackets', type: :dword, data: 1 },
          { name: 'LogSuccessfulConnections', type: :dword, data: 1 }]
  action :create
  recursive true
end