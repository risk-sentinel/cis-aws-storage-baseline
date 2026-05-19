# encoding: UTF-8

control 'C-2.6' do
  title 'Ensure Proper IAM Configuration for EC2 Instances'
  desc  "
    IAM, or Identity and Access Management, is a vital security service used to control and manage access to AWS resources, ensuring only authorized users and services can interact with them. It allows you to create users and groups, set permissions, enforce multi-factor authentication, and implement least privilege principles to enhance security and compliance.

    The rationale behind using IAM is to enhance security by controlling and managing access to AWS resources, ensuring that only authorized users and services can interact with them. This minimizes the risk of unauthorized access and potential security breaches, while also allowing for the implementation of best practices such as multi-factor authentication and least privilege principles, which further strengthen the security and compliance of your AWS environment.
  "
  desc  'rationale', "
    IAM, or Identity and Access Management, is a vital security service used to control and manage access to AWS resources, ensuring only authorized users and services can interact with them. It allows you to create users and groups, set permissions, enforce multi-factor authentication, and implement least privilege principles to enhance security and compliance.

    The rationale behind using IAM is to enhance security by controlling and managing access to AWS resources, ensuring that only authorized users and services can interact with them. This minimizes the risk of unauthorized access and potential security breaches, while also allowing for the implementation of best practices such as multi-factor authentication and least privilege principles, which further strengthen the security and compliance of your AWS environment.
  "
  desc  'check', "
    1. Access the AWS Management Console:
       - Log in to your AWS account and navigate to the AWS Management Console.

    2. Review IAM Users and Roles:
       - Go to the IAM Dashboard and select \"Users\" to review all user accounts.
       - Check each user for appropriate permissions, MFA enablement, and adherence to the principle of least privilege.
       - Similarly, review the \"Roles\" section to ensure roles have the correct permissions and are assigned appropriately.

    3. Check IAM Policies:
       - In the IAM Dashboard, navigate to \"Policies\" and review both AWS managed and customer-managed policies.
       - Ensure that policies follow the principle of least privilege and do not grant excessive permissions.

    4. Analyze IAM Groups:
       - Review the groups in the IAM Dashboard under \"Groups.\"
       - Ensure that users are grouped appropriately and that groups have suitable permissions.

    5. Examine MFA Settings:
       - Verify that Multi-Factor Authentication (MFA) is enabled for all users with console access.
       - In the IAM Dashboard, click on \"Users\" and check the \"Security credentials\" tab for each user to confirm MFA setup.

    6. Audit IAM Activity:
       - Use AWS CloudTrail to review logs of IAM activities, including user logins, policy changes, and other management activities.
       - Ensure that all IAM activities are logged and can be traced back to authorized users.

    7. Implement AWS Config Rules:
       - Enable AWS Config to continuously monitor IAM configurations.
       - Create and apply AWS Config rules that check for compliance with best practices, such as ensuring all users have MFA enabled and policies are not overly permissive.

    8. Generate IAM Reports:
       - Use AWS IAM Access Analyzer to identify permissions granted to resources that can be accessed from outside your AWS account.
       - Generate IAM credential reports from the IAM Dashboard to review the status of all IAM users, including when their passwords were last used and when their access keys were last rotated.

    9. Conduct Regular Reviews:
       - Schedule regular audits to review IAM configurations and policies.
       - Periodically update and refine IAM policies and permissions to ensure ongoing compliance and security.
  "
  desc  'fix', "
    1. Restrict Overly Permissive Policies:
       - Identify and modify any IAM policies that are overly permissive. Update policies to grant the least privilege necessary for users to perform their tasks.
       - Use IAM policy simulator to test and validate the changes to ensure they do not disrupt operations.

    2. Enable Multi-Factor Authentication (MFA):
       - For all users with console access, enable MFA. This adds an additional layer of security.
       - Navigate to the IAM Dashboard, select \"Users,\" and enable MFA under the \"Security credentials\" tab for each user.

    3. Rotate Access Keys:
       - Regularly rotate access keys for IAM users to reduce the risk of compromised credentials.
       - In the IAM Dashboard, select \"Users,\" go to the \"Security credentials\" tab, and create new access keys. Then, disable and delete old access keys after confirming the new keys are functioning correctly.

    4. Remove Unnecessary Users and Roles:
       - Delete any IAM users or roles that are no longer needed to minimize potential security risks.
       - Review each user and role, and remove those that are inactive or no longer required.

    5. Implement Role-Based Access Control (RBAC):
       - Group users by their roles and assign permissions based on job functions.
       - Use IAM groups to manage permissions collectively rather than individually for each user.

    6. Regularly Review and Update IAM Policies:
       - Set up a regular schedule to review and update IAM policies to ensure they remain aligned with security best practices and organizational changes.
       - Use AWS Config and AWS Config Rules to continuously monitor policy changes and ensure compliance.

    7. Enable AWS CloudTrail and AWS Config:
       - Ensure that AWS CloudTrail is enabled to log all IAM activities. Configure it to capture and analyze logs for unauthorized access and policy changes.
       - Enable AWS Config to continuously monitor IAM resource configurations and compliance with best practices.

    8. Conduct Security Awareness Training:
       - Provide regular security training for all users to educate them on best practices for using IAM and the importance of security measures like MFA and least privilege access.

    9. Implement IAM Access Analyzer:
       - Use IAM Access Analyzer to identify and remediate permissions that allow external access to your resources.
       - Regularly review the findings and adjust permissions to ensure that only the necessary external access is granted.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_number:            '2.6'
  tag cis_rid:               '2.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0206r1_rule'
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

  describe 'Ensure Proper IAM Configuration for EC2 Instances' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0206r1_rule.'
  end
end
