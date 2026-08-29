# encoding: UTF-8

control 'C-2.7' do
  title 'Ensure creating IAM User'
  desc  "
    IAM users are individuals whose accounts have been created by the AWS administrator, providing them access to specific AWS resources. These users have undergone identity verification with your organization, ensuring that only authorized personnel can manage and interact with your AWS environment.

    The purpose of creating IAM users and verifying their identities with your organization is to ensure that only authorized individuals have access to AWS resources, enhancing security and preventing unauthorized access. This practice helps maintain control over your AWS environment, ensuring that sensitive data and critical operations are managed by trusted and validated personnel.
  "
  desc  'rationale', "
    IAM users are individuals whose accounts have been created by the AWS administrator, providing them access to specific AWS resources. These users have undergone identity verification with your organization, ensuring that only authorized personnel can manage and interact with your AWS environment.

    The purpose of creating IAM users and verifying their identities with your organization is to ensure that only authorized individuals have access to AWS resources, enhancing security and preventing unauthorized access. This practice helps maintain control over your AWS environment, ensuring that sensitive data and critical operations are managed by trusted and validated personnel.
  "
  desc  'check', "
    1. Access the AWS Management Console:
       - Log in to your AWS account and navigate to the AWS Management Console.

    2. Review IAM Users:
       - Go to the IAM Dashboard and select \"Users.\"
       - Check the list of IAM users to ensure that only authorized users are present.

    3. Check User Details:
       - For each user, click on their name to view their details.
       - Verify the \"User ARN\" and ensure that the user was created by an authorized administrator.
       - Check the \"Security credentials\" tab to see if Multi-Factor Authentication (MFA) is enabled for added security.

    4. Verify Identity Policies:
       - Review the policies attached to each user to ensure they are appropriate for the user's role.
       - Check that permissions follow the principle of least privilege, granting only the necessary access.

    5. Monitor Login Activity:
       - Use AWS CloudTrail to review login activities for each IAM user.
       - Check for any unusual login patterns or unauthorized access attempts.

    6. Use AWS IAM Access Analyzer:
       - Enable IAM Access Analyzer to identify any IAM resources shared outside your AWS account.
       - Review findings to ensure that only verified and authorized users have access to your resources.

    7. Generate IAM Credential Reports:
       - In the IAM Dashboard, go to \"Credential reports\" and generate a report.
       - Review the report for details on all IAM users, including their access key age, password age, and MFA status.

    8. Implement AWS Config Rules:
       - Enable AWS Config to continuously monitor IAM configurations.
       - Create and apply AWS Config rules to check for compliance with identity verification and user management best practices.

    9. Review IAM Roles and Groups:
       - Ensure that roles and groups are properly configured and assigned only to authorized users.
       - Verify that roles have the correct trust relationships and that group memberships are appropriate for the user's responsibilities.

    10. Schedule Regular Audits:
        - Set up regular intervals to audit IAM users and their access rights.
        - Keep records of audit findings and remediation actions to maintain a secure and compliant AWS environment.
  "
  desc  'fix', "
    1. Remove Unauthorized Users:
       - Go to the IAM Dashboard, select \"Users,\" and review the list of users.
       - Identify any unauthorized or unverified users and delete their accounts to prevent unauthorized access.

    2. Enable Multi-Factor Authentication (MFA):
       - For each IAM user, go to the \"Security credentials\" tab and enable MFA.
       - Ensure all users have MFA configured to enhance security and reduce the risk of unauthorized access.

    3. Update User Policies:
       - Review the policies attached to each IAM user.
       - Modify policies to follow the principle of least privilege, ensuring users have only the permissions necessary for their role.
       - Remove any overly permissive policies that could lead to security risks.

    4. Rotate Access Keys:
       - For IAM users with long-lived access keys, create new keys and update the applications or services using them.
       - Delete the old access keys to reduce the risk of compromised credentials.
       - Encourage regular rotation of access keys as a security best practice.

    5. Review and Correct IAM Roles and Groups:
       - Ensure IAM roles are assigned only to authorized users and that trust relationships are properly configured.
       - Check group memberships and remove users who should not be part of specific groups.
       - Update role policies to adhere to the principle of least privilege.

    6. Configure AWS IAM Access Analyzer:
       - Enable IAM Access Analyzer to continuously monitor and analyze access to your IAM resources.
       - Address any findings related to unauthorized or overly broad access permissions.

    7. Implement and Enforce IAM Policies:
       - Create and enforce organizational IAM policies that require identity verification for all users.
       - Use AWS Organizations and Service Control Policies (SCPs) to enforce these policies across all accounts within your organization.

    8. Enable AWS Config and Create Compliance Rules:
       - Enable AWS Config to monitor IAM configurations and compliance.
       - Create AWS Config rules to ensure all users have MFA enabled, policies adhere to least privilege, and access keys are rotated regularly.

    9. Conduct Regular Training:
       - Provide regular security awareness training for all users to emphasize the importance of secure IAM practices.
       - Educate users on how to properly use IAM features and the significance of identity verification.

    10. Schedule Regular Reviews and Audits:
        - Establish a schedule for regular audits of IAM configurations and access controls.
        - Document findings and remediation actions taken during each audit.
        - Continuously improve your IAM practices based on audit results and evolving security threats.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 i 1', 'AC-2 f', 'RA-5 a']
  tag cci:                   ['CCI-002126', 'CCI-000011', 'CCI-001054']
  tag cis_number:            '2.7'
  tag cis_rid:               '2.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0207r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.7'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_7_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.7') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure creating IAM User (attestation-required)' do
      skip "attestation-required: 'Ensure creating IAM User' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_7_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.7 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end