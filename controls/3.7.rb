# encoding: UTF-8

control 'C-3.7' do
  title 'Ensure File-Level Access Control with Mount Targets'
  desc  "
    Mount targets act as gateways, enabling resources to be accessed across different availability zones within a VPC. When you create an EFS file system, mount targets are automatically provisioned in each availability zone associated with the VPC. This ensures high availability and redundancy, allowing seamless and efficient access to the EFS file system from any availability zone.

    Using mount targets ensures seamless access to the EFS file system across different availability zones within a VPC. This automatic provisioning of mount targets in each availability zone provides high availability and redundancy, essential for maintaining uninterrupted data access. It simplifies configuration and enhances the resilience and scalability of the file system architecture.
  "
  desc  'rationale', "
    Mount targets act as gateways, enabling resources to be accessed across different availability zones within a VPC. When you create an EFS file system, mount targets are automatically provisioned in each availability zone associated with the VPC. This ensures high availability and redundancy, allowing seamless and efficient access to the EFS file system from any availability zone.

    Using mount targets ensures seamless access to the EFS file system across different availability zones within a VPC. This automatic provisioning of mount targets in each availability zone provides high availability and redundancy, essential for maintaining uninterrupted data access. It simplifies configuration and enhances the resilience and scalability of the file system architecture.
  "
  desc  'check', "
    TODO: check content missing in source XCCDF
  "
  desc  'fix', "
    Control access by modifying mount targets in each availability zone.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.7'
  tag cis_rid:               '3.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0307r1_rule'
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

  describe 'Ensure File-Level Access Control with Mount Targets' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0307r1_rule.'
  end
end
