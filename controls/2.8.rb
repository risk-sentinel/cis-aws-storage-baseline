# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure the Creation of IAM Groups'
  desc  "
    IAM Groups are collections of users that share the same permissions for accessing AWS resources. For instance, you can create a group named \"Administrators,\" which includes users who require full access to your AWS environment. This simplifies permission management by assigning common access policies to all members of the group.

    IAM groups in AWS simplify permission management by grouping users with similar access needs and applying common access policies, reducing administrative overhead and enhancing security through the principle of least privilege. This approach ensures consistency, scalability, and ease of auditing, strengthening the overall security posture of the AWS environment.
  "
  desc  'rationale', "
    IAM Groups are collections of users that share the same permissions for accessing AWS resources. For instance, you can create a group named \"Administrators,\" which includes users who require full access to your AWS environment. This simplifies permission management by assigning common access policies to all members of the group.

    IAM groups in AWS simplify permission management by grouping users with similar access needs and applying common access policies, reducing administrative overhead and enhancing security through the principle of least privilege. This approach ensures consistency, scalability, and ease of auditing, strengthening the overall security posture of the AWS environment.
  "
  desc  'check', "
    1. Enable AWS CloudTrail:
       - Navigate to the AWS Management Console and open the CloudTrail service.
       - Create a new trail or ensure that an existing trail is configured to capture API activity in your AWS account.
       - Verify that CloudTrail is recording events related to IAM actions, including changes to IAM groups.

    2. Review CloudTrail Logs:
       - Access the CloudTrail console and navigate to the Event History or Insights section.
       - Filter the logs to focus on IAM-related events, such as CreateGroup, AddUserToGroup, RemoveUserFromGroup, and PutGroupPolicy.
       - Analyze the logs to track changes made to IAM groups, including user additions/removals and modifications to group policies.

    3. Utilize AWS Config:
       - Open the AWS Config console and ensure that AWS Config is enabled for your AWS account.
       - Set up AWS Config rules to monitor IAM configurations, including IAM groups.
       - Configure rules to check for compliance with security standards or organizational policies regarding IAM group settings and permissions.

    4. Check IAM Console:
       - Access the IAM console in the AWS Management Console.
       - Navigate to the \"Groups\" section to view a list of IAM groups in your account.
       - Review the details of each group, including its members and attached policies, to ensure they align with your security requirements.
  "
  desc  'fix', "
    1. CloudTrail and AWS Config Configuration:
       - If CloudTrail or AWS Config is not enabled, configure them to capture and monitor IAM activities and configurations respectively. Enable logging and set up appropriate rules to track IAM group changes and ensure compliance.

    2. Review CloudTrail Logs for Anomalies:
       - Regularly review CloudTrail logs to identify any unauthorized or unexpected changes to IAM groups.
       - Investigate any anomalies detected in the logs, such as unauthorized user additions or policy modifications, and take appropriate action to rectify them.

    3. AWS Config Remediation Rules:
       - Define AWS Config rules to automatically detect non-compliant IAM group configurations.
       - Configure remediation actions within AWS Config to automatically revert any deviations from the desired IAM group settings back to the compliant state.

    4. IAM Group Cleanup:
       - Periodically review IAM groups to ensure they are still necessary and relevant.
       - Remove any unused or obsolete IAM groups to reduce the attack surface and simplify permission management.

    5. Permissions Review:
       - Regularly review the permissions assigned to IAM groups to ensure they follow the principle of least privilege.
       - Remove any excessive permissions or policies that are not required for the group's intended purpose.

    6. Security Best Practices:
       - Implement security best practices for IAM, such as enforcing multi-factor authentication (MFA) for privileged IAM users and regularly rotating access keys.
       - Train IAM administrators and users on security best practices to prevent inadvertent misconfigurations and unauthorized access.

    7. Documentation and Monitoring:
       - Document IAM group configurations, policies, and access controls to maintain an audit trail and facilitate future audits.
       - Set up monitoring alerts to notify administrators of any suspicious activities related to IAM groups.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 c', 'SA-3 a', 'RA-5 a']
  tag nist_r4:               ['AC-2 c', 'RA-5 a', 'SA-3 a']
  tag cci:                   ['CCI-002113', 'CCI-000615', 'CCI-001054']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0208r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  # Procedural/operational control — the CIS Storage benchmark check-content is a
  # console setup/operational procedure, not an AWS-API-assertable state. Converted
  # to evidence-class attestation: resolves the per-control
  # override else attestation_uri(:boundary, 'C-2.8'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_8_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.8') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure the Creation of IAM Groups (attestation-required)' do
      skip "attestation-required: 'Ensure the Creation of IAM Groups' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_8_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.8 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end