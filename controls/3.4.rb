# encoding: UTF-8

control 'C-3.4' do
  title 'Ensure controlling Network access to EFS Services'
  desc  "
    It's important that you secure access to your resources on your AWS VPC network. There are several ways to ensure that you control what traffic is accessing your resources. Some of which include tightening down network layer security using a Security Group and a NACL within the VPC console. You can also tighten down Security Groups within your EC2 console and by using AWS IAM. Maintaining network security is a high priority to ensure that no unauthorized users can access the data stored on your EFS service.

    Maintaining network security is a best practice essential for keeping your data safe and secure.
  "
  desc  'rationale', "
    It's important that you secure access to your resources on your AWS VPC network. There are several ways to ensure that you control what traffic is accessing your resources. Some of which include tightening down network layer security using a Security Group and a NACL within the VPC console. You can also tighten down Security Groups within your EC2 console and by using AWS IAM. Maintaining network security is a high priority to ensure that no unauthorized users can access the data stored on your EFS service.

    Maintaining network security is a best practice essential for keeping your data safe and secure.
  "
  desc  'check', "
    TODO: check content missing in source XCCDF
  "
  desc  'fix', "
    Implement network security access controls.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'SI-4 (5)', 'AC-17 (2)']
  tag cci:                   ['CCI-000213', 'CCI-002663', 'CCI-000068']
  tag cis_number:            '3.4'
  tag cis_rid:               '3.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0304r1_rule'
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

  describe 'Ensure controlling Network access to EFS Services' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0304r1_rule.'
  end
end
