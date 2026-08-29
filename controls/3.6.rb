# encoding: UTF-8

control 'C-3.6' do
  title 'Ensure Secure Ports'
  desc  "
    Securing network ports is essential for protecting AWS storage services like Amazon S3, EFS, and EBS. By configuring security groups and network access control lists (NACLs) to allow only necessary traffic, you minimize the risk of unauthorized access. Regular audits and monitoring of port usage ensure that only approved ports and protocols are operational, enhancing the overall security of your AWS storage environment.

    By limiting traffic to only necessary and approved ports and protocols, you reduce the attack surface and enhance the overall security of your storage environment. Regular audits and monitoring further ensure that security measures remain effective and up-to-date, safeguarding your data from emerging threats.
  "
  desc  'rationale', "
    Securing network ports is essential for protecting AWS storage services like Amazon S3, EFS, and EBS. By configuring security groups and network access control lists (NACLs) to allow only necessary traffic, you minimize the risk of unauthorized access. Regular audits and monitoring of port usage ensure that only approved ports and protocols are operational, enhancing the overall security of your AWS storage environment.

    By limiting traffic to only necessary and approved ports and protocols, you reduce the attack surface and enhance the overall security of your storage environment. Regular audits and monitoring further ensure that security measures remain effective and up-to-date, safeguarding your data from emerging threats.
  "
  desc  'check', "
    1. Review Security Group Configurations:
         1. Navigate to \"Security Groups\" under \"Network & Security\".
         2. Verify that security groups are configured to allow only necessary inbound and outbound traffic.
         3. Ensure rules are in place to restrict access to critical storage services, such as Amazon S3, EFS, and EBS.

    2. Check Network Access Control Lists (NACLs):
       - Steps:
         1. Navigate to \"Network ACLs\" under \"Security\".
         2. Ensure NACLs are configured to control traffic to and from subnets, allowing only necessary ports and protocols.
         3. Verify that rules are implemented to deny unauthorized access.

    3. Monitor VPC Flow Logs:
       - Steps:
         1. Enable VPC Flow Logs for each VPC.
         2. Regularly review flow logs to monitor traffic and identify any unauthorized access attempts or anomalies.
         3. Investigate and remediate any unusual traffic patterns.

    4. Inspect IAM Policies and Roles:
       - Steps:
         1. Review IAM policies to ensure they enforce least privilege principles for access to storage services.
         2. Verify that roles are appropriately assigned and used to control access to security groups and NACLs.

    5. Enable and Review AWS CloudTrail Logs:
       - Steps:
         1. Ensure CloudTrail is enabled in all regions.
         2. Regularly review CloudTrail logs for any changes to security groups, NACLs, and IAM policies.
         3. Set up alerts for critical security events related to port configurations.

    6. Conduct Regular Penetration Testing:
       - Steps:
         1. Conduct tests to identify vulnerabilities in port configurations.
         2. Review findings and implement necessary security measures to address identified issues.
         3. Ensure compliance with AWS penetration testing policies.

    7. Verify Encryption in Transit:
       - Steps:
         1. Ensure that data encryption is enabled for data in transit.
         2. Verify that encryption keys are managed securely using AWS Key Management Service (KMS).
         3. Check that all communication with storage services is encrypted.

    8. Implement and Review Security Best Practices:
       - Steps:
         1. Implement recommended best practices for securing network ports and storage services.
         2. Regularly review and update security configurations to align with evolving best practices.
         3. Conduct periodic training for staff on security best practices and AWS configurations.
  "
  desc  'fix', "
    Close the ports that are open without a reason, at both layers.

    1. Security groups are stateful and allow-only. Remove inbound rules that are
       not tied to a specific consumer, and prefer source-security-group references
       over CIDR ranges.
    2. Network ACLs are stateless: an inbound allow needs a matching outbound rule
       for the ephemeral port range, so an over-tight NACL breaks traffic while an
       over-broad one adds nothing. Use NACLs for coarse subnet-level denies and
       leave fine-grained control to security groups.
    3. Reach storage services over VPC endpoints rather than opening egress to the
       internet. An interface endpoint for EFS, or a gateway endpoint for S3, keeps
       the traffic on the AWS network and lets you drop broad outbound rules.
    4. Re-check after any change that the file system still mounts, then confirm no
       rule allows `0.0.0.0/0` on an administrative port.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'SI-4 (11)', 'AC-17 (1)']
  tag nist_r4:               ['AC-17 (1)', 'AC-3', 'SI-4 (11)']
  tag cci:                   ['CCI-000213', 'CCI-002668', 'CCI-000067']
  tag cis_number:            '3.6'
  tag cis_rid:               '3.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0306r1_rule'
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

  # EFS uses NFS (TCP 2049); no security group may expose it to the internet.
  aws_security_groups.group_ids.each do |gid|
    describe aws_security_group(group_id: gid) do
      it { should_not allow_in(port: 2049, ipv4_range: '0.0.0.0/0') }
    end
  end
end