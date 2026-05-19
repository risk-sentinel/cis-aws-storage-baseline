# encoding: UTF-8

control 'C-3.9' do
  title 'Ensure using VPC endpoints - EFS'
  desc  "
    With AWS PrivateLink, VPC Endpoints allow services to communicate within AWS using private IP addresses within approved CIDR ranges. This communication can be achieved without the need for a VPN, ensuring secure and efficient data transfer.

    The rationale behind using AWS PrivateLink with VPC Endpoints is to enable secure and efficient communication between services within AWS. By using private IP addresses within approved CIDR ranges, it eliminates the need for a VPN, reducing complexity and potential points of failure. This approach enhances security, reduces latency, and ensures data remains within the AWS network, aligning with best practices for secure and reliable cloud architecture.
  "
  desc  'rationale', "
    With AWS PrivateLink, VPC Endpoints allow services to communicate within AWS using private IP addresses within approved CIDR ranges. This communication can be achieved without the need for a VPN, ensuring secure and efficient data transfer.

    The rationale behind using AWS PrivateLink with VPC Endpoints is to enable secure and efficient communication between services within AWS. By using private IP addresses within approved CIDR ranges, it eliminates the need for a VPN, reducing complexity and potential points of failure. This approach enhances security, reduces latency, and ensures data remains within the AWS network, aligning with best practices for secure and reliable cloud architecture.
  "
  desc  'check', "
    Creating a FIPS compliant interface endpoint for EFS:
    1.  Navigate to VPC Console: https://console.aws.amazon.com/vpc/.
    2.  Select \"Endpoints\" on the sidebar.
    3. Select \"Create endpoint.
    4. Name the endpoint.
    5. Copy and paste this services into the services bar:  com.amazonaws.region.elasticfilesystem-fips - replace \"region: with us-east-1 or whatever region you're using.
    6. Select your VPC.
    7. For subnets, select the availability zone and then select private subnet.
    8. Select the Security Group for the VPC endpoint.
    9. For policy: select \"full access\".
    10. Create a tag for future reference / granular IAM permissions.
    11. Create endpoint.
  "
  desc  'fix', "
    Use VPC Endpoints in tandem with AWS Private Link to secure your EFS connections.
  "
  tag severity:              'medium'
  tag nist:                  ['SI-4 (11)', 'AU-7 a', 'AC-17 (2)', 'AC-8 a']
  tag cci:                   ['CCI-002668', 'CCI-001875', 'CCI-000068', 'CCI-000051']
  tag cis_number:            '3.9'
  tag cis_rid:               '3.9'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0309r1_rule'
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

  describe 'Ensure using VPC endpoints - EFS' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0309r1_rule.'
  end
end
