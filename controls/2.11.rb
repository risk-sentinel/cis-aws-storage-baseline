# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure Secure Password Policy Implementation'
  desc  "
    Password policies outline the appropriate parameters for password configuration within an organization.

    Clear password policies provide essential guidelines for maintaining strong authentication practices, reducing the risk of unauthorized access and data breaches within an organization. By enforcing requirements for complex passwords and regular updates, these policies help bolster cybersecurity defenses and ensure compliance with industry standards and regulations.
  "
  desc  'rationale', "
    Password policies outline the appropriate parameters for password configuration within an organization.

    Clear password policies provide essential guidelines for maintaining strong authentication practices, reducing the risk of unauthorized access and data breaches within an organization. By enforcing requirements for complex passwords and regular updates, these policies help bolster cybersecurity defenses and ensure compliance with industry standards and regulations.
  "
  desc  'check', "
    1. Review IAM Policies:
       - Access the IAM console in the AWS Management Console.
       - Navigate to the \"Password Policy\" section to review the current password policy settings.
       - Ensure that the password policy aligns with industry best practices and organizational security requirements, including parameters such as minimum length, complexity requirements, and password expiration.

    2. AWS Config Rules:
       - Configure AWS Config rules to monitor IAM password policies.
       - Set up rules to check for compliance with password policy requirements, such as minimum length, complexity, and expiration settings.
       - Use AWS Config to continuously assess the configuration of IAM password policies and identify any non-compliant settings.

    3. CloudTrail Analysis:
       - Access the CloudTrail console and review logs related to IAM password policy changes.
       - Look for API calls related to modifications of password policy settings.
       - Analyze the logs to ensure that password policy changes are authorized and adhere to organizational security standards.

    4. Manual Review:
       - Manually inspect the IAM password policy settings to verify compliance with security requirements.
       - Check for parameters such as minimum password length, complexity requirements (e.g., uppercase, lowercase, special characters), and password expiration settings.
  "
  desc  'fix', "
    1. Revise and Update Password Policies:
       - Navigate to the IAM dashboard in the AWS Management Console.
       - Go to the \"Account settings\" section to review and adjust the password policy.
       - Strengthen the policy by setting requirements for password length, complexity (including uppercase, lowercase, numbers, and special characters), and rotation policies.

    2. Enforce Password Changes:
       - If the audit reveals passwords that do not comply with the updated policy, require users to change their passwords immediately.
       - Implement mandatory password updates at regular intervals to ensure ongoing compliance with the policy.

    3. Enable AWS Config for Continuous Compliance:
       - Use AWS Config to continuously monitor and record IAM password policies.
       - Set up AWS Config rules that automatically check compliance with your organization's password policy standards.

    4. Utilize Multi-Factor Authentication (MFA):
       - Enable MFA for an additional layer of security on all user accounts, especially for accounts with elevated permissions.
       - Regularly audit the use of MFA across your AWS environment to ensure it is enabled and functioning correctly.

    6. Automate Alerts and Responses:
       - Set up real-time alerts for any non-compliant changes to password policies or unexpected password resets.
       - Automate responses where possible to enforce compliance immediately when a deviation from the password policy is detected.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-18 a', 'SC-7 a', 'AC-2 (2)', 'AC-2 c']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-AAM', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-SVC-EIS']
  tag nist_r4:               ['AC-18 a', 'AC-2 (2)', 'AC-2 c', 'SC-7 a']
  tag cci:                   ['CCI-002323', 'CCI-001097', 'CCI-001682', 'CCI-002113']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0211r1_rule'
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

  describe aws_iam_password_policy do
    it { should exist }
    its('minimum_password_length') { should be >= 14 }
    it { should require_symbols }
    it { should require_numbers }
    it { should require_uppercase_characters }
    it { should require_lowercase_characters }
  end
end