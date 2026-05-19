# encoding: UTF-8

control 'C-1.4' do
  title 'Ensure to create AWS IAM Policies'
  desc  "
    AWS IAM policies, specify the desired permissions for accessing AWS resources and define the 
    conditions under which those permissions are granted. Configure the appropriate policies to keep 
    your resources secure.

    Managing AWS IAM policies is crucial to safeguard your backups from unauthorized access, 
    ensuring that only approved users can manipulate or view sensitive data.
  "
  desc  'rationale', "
    AWS IAM policies, specify the desired permissions for accessing AWS resources and define the 
    conditions under which those permissions are granted. Configure the appropriate policies to keep 
    your resources secure.

    Managing AWS IAM policies is crucial to safeguard your backups from unauthorized access, 
    ensuring that only approved users can manipulate or view sensitive data.
  "
  desc  'check', "
    To create a role for AWS Backup, follow these steps:
    1. Navigate to the \"IAM Dashboard\" in the AWS Console.
    2. Select \"Roles\" from the left-hand menu.
    3. Click on the \"Create Role\" button.
    4. Choose \"AWS Service\" as the trusted entity.
    5. Select \"AWS Backup\" as the service that will use this role.
    6. Choose a policy to apply to the role or create a custom policy.
    7. Review the role details and provide a meaningful name for the role.
    8. Click on \"Create Role\" to finalize the creation of the role for AWS Backup.
  "
  desc  'fix', "
    AWS IAM policies, restricting access to backup resources, and implementing additional security 
    measures to prevent future incidents.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.4'
  tag cis_rid:               '1.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0104r1_rule'
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

  describe 'Ensure to create AWS IAM Policies' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0104r1_rule.'
  end
end
