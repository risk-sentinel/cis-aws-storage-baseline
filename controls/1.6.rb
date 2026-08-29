# encoding: UTF-8

control 'C-1.6' do
  title 'Ensure AWS Backup with Service Linked Roles'
  desc  "
    AWS Service Linked Roles are IAM roles designed specifically for AWS Backup. These roles come
    with default configurations allowing access to all AWS resources by default.

    While Service Linked Roles offer quick deployment, using default configurations isn't 
    recommended for security best practices.
  "
  desc  'rationale', "
    AWS Service Linked Roles are IAM roles designed specifically for AWS Backup. These roles come
    with default configurations allowing access to all AWS resources by default.

    While Service Linked Roles offer quick deployment, using default configurations isn't 
    recommended for security best practices.
  "
  desc  'check', "
    Create service-linked role for AWS Backup:
    You don't need to create a service-linked role manually. AWS Backup automatically creates it when you list resources to back up, set up cross-account backup, or perform backups using the AWS Management Console, AWS CLI, or AWS API.
    If you delete this role, you can recreate it by following the same steps. AWS Backup will create it for you again when needed.
  "
  desc  'fix', "
    Assess your organization's needs to determine whether to utilize Service Linked Roles
    for AWS backups.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.6'
  tag cis_rid:               '1.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0106r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe aws_iam_role(role_name: 'AWSServiceRoleForBackup') do
    it { should exist }
  end
end