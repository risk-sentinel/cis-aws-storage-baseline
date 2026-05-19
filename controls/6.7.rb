# encoding: UTF-8

control 'C-6.7' do
  title 'Ensure proper configuration of the Launch Settings'
  desc  "
    Set up and verify the launch settings to ensure systems and applications start correctly and securely. This includes defining startup parameters, specifying required resources, and configuring security settings to prevent unauthorized changes. Regularly review and update these settings to align with best practices and organizational requirements, ensuring optimal performance and security at launch.

    Proper configuration of launch settings is crucial for ensuring that systems and applications start securely and perform optimally. Defining startup parameters and resource requirements prevents potential issues and enhances efficiency. Regular reviews and updates to these settings help maintain alignment with best practices and evolving organizational needs, thereby strengthening security and operational reliability from the moment of launch.
  "
  desc  'rationale', "
    Set up and verify the launch settings to ensure systems and applications start correctly and securely. This includes defining startup parameters, specifying required resources, and configuring security settings to prevent unauthorized changes. Regularly review and update these settings to align with best practices and organizational requirements, ensuring optimal performance and security at launch.

    Proper configuration of launch settings is crucial for ensuring that systems and applications start securely and perform optimally. Defining startup parameters and resource requirements prevents potential issues and enhances efficiency. Regular reviews and updates to these settings help maintain alignment with best practices and evolving organizational needs, thereby strengthening security and operational reliability from the moment of launch.
  "
  desc  'check', "
    The settings can be changed after instances have been launched, but a new instance must be launched for new launch settings to take effect. 
    1. Select launch settings on the source server page
    2. Configure launch settings
    	- On the launch settings page, next to general launch, select \"edit\"
    3. Configure EC2 launch template
    	- Enable auto assign public IP and change the instance type to a t2.medium
    4. Set version to default in the console
    5. Set the default version that was just created to default version
    6. Return to the dashboard and confirm your configurations are correct.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-18 a', 'IA-5 (1) (e)', 'AC-2 c', 'CM-6 a']
  tag cci:                   ['CCI-002323', 'CCI-000200', 'CCI-002113', 'CCI-000363']
  tag cis_number:            '6.7'
  tag cis_rid:               '6.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0607r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe 'Ensure proper configuration of the Launch Settings' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0607r1_rule.'
  end
end
