# cb-cis-level1-windows10-1511

### Background:

This cookbook is developed based on CIS Level1 security standards for Windows 10. To know more about the settings and configurations please refer my CIS Level1 inspec profile. [![cis-windows10-1511-level1](https://github.com/Prabhuapr1984/cis-windows10-1511-level1)

### NOTE: 

    - This cookbook can be used to apply one time hardening as well as continous hardening to avoid the configuration drift, Please tested in your Dev, Stage environment before you apply into Production.

### Warning ⚠️

    - Do proper testing against your organisation security standards, operational standards before you apply this hardening as this may lockdown your windows and other applications.

## Requirements :

    - Chef Infra Client
        or
    - Chef Workstation

## Optional Requirement :

    - SecurityPolicyDsc => Powershell DSC Module (if you apply "section_1_dsc.rb, section_2_dsc.rb" recipe using DSC, since i'm not using DSC  due to consistent check issue when chef client runs, because the chef client runs every 30 mins which conflicts with DSC)

### Supported OS Platforms :

    - Windows 10

### Minimum Chef Infra client version :

    - Chef >= 14.0 (Change the metadata file if you are running on less than 14 chef client)

## Required Resources :

    - No additional resources are required.

## Required Libraries :

    - audit_policy_provider
    - audit_policy_resource

## Required Templates :

    - security_policy.inf.erb (see included).

### Recipes Usage :

    - section_2 (Registry, command(execute), PowerShell)
    - section_9 (Registry)
    - section_17 (Audit policies - using libraries)
    - section_18 (Registry)
    - section_19 (PowerShell), Note: this section is option configuration as these settings are applicable when the user is logged on.
    - security_policy (It uses native 'secedit.exe' tool to apply .inf based configuration which will create based on attributed=> sec_policy.rb)

## Can use other deployment tools to harden the windows 10 to complies with CIS level1?

```ruby  

    - Yes, You can also leverage System Center Configuration Manager (SCCM), Altris, IBM BigFix, GPO, etc,. other deployment tools for one time hardening using the file included using the powershell command or native cmd.exe 'cb-cis-level1-windows10-1511.inf' [see powershell resource section in 'security_policy.rb' recipe].
    
```
## Contributors :

    - Author:: Prabu Jaganathan ((mailto:jaganp.architect@gmail.com))

```text

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
