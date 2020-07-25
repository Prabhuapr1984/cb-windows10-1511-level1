# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: security_policy
#
# Copyright:: 2020, The Authors, All Rights Reserved.

directory 'C:\\cis-level1-harden' do # If chef client installed, use this path '#{Chef::Config[:file_cache_path]}'
  action :create
  recursive true
end

template 'C:\\Windows\\security\\templates\\cb-cis-level1-windows10-1511.inf' do
  source 'security_policy.inf.erb'
end

powershell_script 'Apply_cb-cis-level1-windows10-1511_hardening' do
  cwd 'C:\\Windows\\security'
  code <<-EOH
     $arguments = "/c secedit.exe /configure /cfg .\\templates\\cb-cis-level1-windows10-1511.inf /db .\\database\\cb-cis-level1-windows10-1511.sdb /overwrite /log .\\logs\\cb-cis-level1-windows10-1511.log /quiet"
     [diagnostics.process]::start("cmd.exe", $arguments).waitforexit() | Out-Null
     sleep -Seconds 20
  EOH
end
