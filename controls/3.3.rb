# encoding: UTF-8

control 'C-3.3' do
  title 'Ensure EFS and VPC Integration'
  desc  "
    You can use EFS as a network file system across availability zones on a virtual private cloud. This capability allows the organization to create a highly available file sharing solution. Leveraging AWS VPC and EC2 in tandem with AWS EFS makes for a highly available and scalable cloud file storage solution.

    Redundancy and scalability are crucial for maintaining uninterrupted services. By integrating these AWS services, users can harness the full power of AWS, ensuring a resilient and scalable infrastructure.
  "
  desc  'rationale', "
    You can use EFS as a network file system across availability zones on a virtual private cloud. This capability allows the organization to create a highly available file sharing solution. Leveraging AWS VPC and EC2 in tandem with AWS EFS makes for a highly available and scalable cloud file storage solution.

    Redundancy and scalability are crucial for maintaining uninterrupted services. By integrating these AWS services, users can harness the full power of AWS, ensuring a resilient and scalable infrastructure.
  "
  desc  'check', "
    ### Audit Procedures for AWS Redundancy and Scalability

    1. Create Mount Targets in Each Availability Zone: Ensure EFS is attached in each availability zone by creating mount targets in each subnet. Although multiple subnets can exist per availability zone, verify that EFS is configured to work with one subnet per zone to maintain redundancy.

    2. Monitor EFS with CloudWatch: Use AWS CloudWatch to automatically monitor your EFS service. Check that alarms are configured and logs and events are tracked effectively, providing real-time insights into the performance and health of your file systems.
  "
  desc  'fix', "
    Create an EC2 instance in each availability zone within your VPC.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'SI-4 (5)', 'AC-8 a', 'CM-6 a']
  tag cci:                   ['CCI-001199', 'CCI-002663', 'CCI-000051', 'CCI-000363']
  tag cis_number:            '3.3'
  tag cis_rid:               '3.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0303r1_rule'
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

  describe 'Ensure EFS and VPC Integration' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0303r1_rule.'
  end
end
