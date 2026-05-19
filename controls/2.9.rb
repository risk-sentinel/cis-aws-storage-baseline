# encoding: UTF-8

control 'C-2.9' do
  title 'Ensure Granular Policy Creation'
  desc  "
    Granular policies are meticulously tailored to AWS resources, ensuring precision in access control measures.

    Emphasizing granular policies in AWS ensures that access control measures are precisely aligned with the requirements of each resource, bolstering security and minimizing unauthorized access. By tailoring policies to specific resources, organizations can adhere more closely to the principle of least privilege, mitigating risks and maintaining compliance with regulatory standards.
  "
  desc  'rationale', "
    Granular policies are meticulously tailored to AWS resources, ensuring precision in access control measures.

    Emphasizing granular policies in AWS ensures that access control measures are precisely aligned with the requirements of each resource, bolstering security and minimizing unauthorized access. By tailoring policies to specific resources, organizations can adhere more closely to the principle of least privilege, mitigating risks and maintaining compliance with regulatory standards.
  "
  desc  'check', "
    1. Review IAM Policies:
       - Access the IAM console in the AWS Management Console.
       - Navigate to the \"Policies\" section to view all IAM policies.
       - Examine each policy to ensure they are finely tuned and specific to the resources they are intended to control access to.

    2. Utilize AWS Config:
       - Open the AWS Config console and ensure that AWS Config is enabled for your AWS account.
       - Set up Config rules to monitor IAM policies for granularity.
       - Configure rules to detect policies that are overly broad or provide unnecessary permissions.

    3. CloudTrail Analysis:
       - Access the CloudTrail console and review the logs.
       - Look for API calls related to IAM policy modifications.
       - Analyze the logs to ensure that policy changes align with the principles of granular access control.

    4. Manual Review:
       - Conduct manual reviews of IAM policies and their associated resources.
       - Verify that policies are scoped to specific resources and actions, rather than providing blanket permissions.

    5. Automated Scanning:
       - Utilize third-party AWS security tools that offer automated scanning and analysis of IAM policies for granularity.
       - Configure these tools to regularly scan and identify any policies that may not adhere to granular access control principles.

    6. Continuous Monitoring:
       - Implement continuous monitoring solutions to track changes to IAM policies in real-time.
       - Set up alerts to notify administrators of any policy modifications that may deviate from granular access control best practices.
  "
  desc  'fix', "
    1. Policy Refinement:
       - Review existing IAM policies to identify those that are overly broad or lack granularity.
       - Refine these policies to restrict permissions to only the resources and actions necessary for each user or group.

    2. IAM Policy Simulator:
       - Utilize the IAM Policy Simulator in the AWS Management Console to test the effectiveness of policy changes.
       - Simulate various access scenarios to ensure that policies are granting the intended level of access without unintended consequences.

    3. Access Reviews:
       - Conduct regular access reviews to ensure that IAM policies remain aligned with the principle of least privilege.
       - Identify and remove any unnecessary permissions or policies that grant excessive access to resources.

    4. AWS Config Remediation:
       - Configure AWS Config rules to automatically remediate non-compliant IAM policies.
       - Set up remediation actions to adjust policies to adhere to granular access control principles automatically.

    5. Employee Training:
       - Provide training and guidance to IAM administrators on best practices for crafting granular policies.
       - Ensure that administrators understand the importance of restricting permissions to only what is necessary for each user or group.

    6. Monitoring and Alerting:
       - Implement continuous monitoring solutions to detect and alert on any deviations from granular access control policies.
       - Set up alerts to notify administrators of any unauthorized changes to IAM policies in real-time.

    7. Documentation and Documentation:
       - Document changes made to IAM policies and keep records of policy adjustments.
       - Maintain up-to-date documentation on IAM policies and access controls for reference during audits and compliance assessments.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 c', 'RA-5 a']
  tag cci:                   ['CCI-002113', 'CCI-001054']
  tag cis_number:            '2.9'
  tag cis_rid:               '2.9'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0209r1_rule'
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

  describe 'Ensure Granular Policy Creation' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0209r1_rule.'
  end
end
