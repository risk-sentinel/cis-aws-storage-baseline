# encoding: UTF-8

control 'C-2.2' do
  title 'Ensure configuring Security Groups'
  desc  "
    Security groups are your first line of defense for the EC2 instance. A security group is a firewall that controls inbound and outbound traffic.

    Security groups play a critical role in maintaining the security of your AWS resources. It is advisable to restrict traffic to only what is necessary for accessing your instance, thereby minimizing potential security risks.
  "
  desc  'rationale', "
    Security groups are your first line of defense for the EC2 instance. A security group is a firewall that controls inbound and outbound traffic.

    Security groups play a critical role in maintaining the security of your AWS resources. It is advisable to restrict traffic to only what is necessary for accessing your instance, thereby minimizing potential security risks.
  "
  desc  'check', "
    Open traffic for SSH, HTTP, and HTTPS. Make sure to allow traffic from anywhere, unless you will be accessing the instance from a secure workstation or server with a static IP address.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SI-4 (11)', 'SC-23']
  tag cci:                   ['CCI-002668', 'CCI-001184']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0202r1_rule'
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

  aws_security_groups.group_ids.each do |gid|
    describe aws_security_group(group_id: gid) do
      it { should_not allow_in(port: 22, ipv4_range: '0.0.0.0/0') }
    end
  end
end