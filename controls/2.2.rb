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
    From Command Line:

    List every security group in the account that allows inbound traffic from
    any source address:

    ```
    aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].[GroupId,GroupName]' --output table
    ```

    For each group returned, review the rule that opened it. The control fails if
    any security group permits inbound TCP 22 from `0.0.0.0/0`, and the same
    reasoning applies to 3389 on Windows hosts: administrative access must come
    from a bastion, a client security group, or a named corporate range, never
    from the internet.

    Inbound 80 and 443 from `0.0.0.0/0` is expected on an internet-facing load
    balancer. Verify it is not also present on the instances behind it, which
    should accept traffic only from the load balancer's security group.
  "
  desc  'fix', "
    Scope each security group to the traffic the workload actually needs, and never
    expose administrative ports to the internet.

    1. Identify the rules allowing `0.0.0.0/0` (or `::/0`) inbound:

        ```
        aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 --query 'SecurityGroups[].[GroupId,GroupName]' --output table
        ```

    2. Revoke any such rule on port 22, and on 3389 for Windows hosts:

        ```
        aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0
        ```

    3. Replace it with access scoped to the source that genuinely needs it - a
       bastion or client security group, or a named corporate CIDR:

        ```
        aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --source-group <bastion-sg-id>
        ```

    4. Better still, remove inbound administrative access altogether and reach the
       instance through AWS Systems Manager Session Manager, which needs no open
       port and leaves an auditable session record.

    Public HTTP and HTTPS from `0.0.0.0/0` is legitimate for an internet-facing load
    balancer. It is not legitimate on the instances behind it, which should accept
    traffic only from the load balancer's security group.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (11)', 'SC-23']
  tag nist_r4:               ['SC-23', 'SI-4 (11)']
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