#
# Cookbook:: cb-cis-level1-windows10-1511
# Recipe:: default
#
# Copyright:: 2020, The Authors, All Rights Reserved.

return unless platform_family?('windows')

include_recipe 'cb-cis-level1-windows10-1511::security_policy'
include_recipe 'cb-cis-level1-windows10-1511::section_2'
include_recipe 'cb-cis-level1-windows10-1511::section_9'
include_recipe 'cb-cis-level1-windows10-1511::section_17'
include_recipe 'cb-cis-level1-windows10-1511::section_18'
include_recipe 'cb-cis-level1-windows10-1511::section_19'
