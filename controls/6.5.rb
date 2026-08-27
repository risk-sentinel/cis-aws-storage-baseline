# encoding: UTF-8

control 'C-6.5' do
  title 'Ensure proper IAM configuration for AWS Elastic Disaster Recovery'
  desc  "
    Set up and maintain Identity and Access Management (IAM) roles and policies specifically for AWS Elastic Disaster Recovery. This includes defining least-privilege access for users and services, creating roles for automated processes, and enforcing multi-factor authentication (MFA) for added security. Regularly review and update IAM policies to adapt to changes in the organization and to maintain compliance with security best practices, ensuring that only authorized personnel and services can access and manage disaster recovery resources.

    Proper IAM configuration for AWS Elastic Disaster Recovery ensures that only authorized users and services have access to critical recovery functions, reducing the risk of unauthorized access and potential security breaches. Implementing least-privilege access and MFA enhances security by limiting permissions and adding an extra layer of authentication. Regular reviews and updates of IAM policies help maintain security compliance and adapt to organizational changes, ensuring continuous protection of disaster recovery resources.
  "
  desc  'rationale', "
    Set up and maintain Identity and Access Management (IAM) roles and policies specifically for AWS Elastic Disaster Recovery. This includes defining least-privilege access for users and services, creating roles for automated processes, and enforcing multi-factor authentication (MFA) for added security. Regularly review and update IAM policies to adapt to changes in the organization and to maintain compliance with security best practices, ensuring that only authorized personnel and services can access and manage disaster recovery resources.

    Proper IAM configuration for AWS Elastic Disaster Recovery ensures that only authorized users and services have access to critical recovery functions, reducing the risk of unauthorized access and potential security breaches. Implementing least-privilege access and MFA enhances security by limiting permissions and adding an extra layer of authentication. Regular reviews and updates of IAM policies help maintain security compliance and adapt to organizational changes, ensuring continuous protection of disaster recovery resources.
  "
  desc  'check', "
    To create DRS Agent User, follow following steps:
    1. Navigate to the AWS IAM Console - https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1#/home.
    2. Create new user. This user will only be able to access the Elastic disaster recovery agent installation resource. Accordingly, name the user \"DSRuser\".
    3. Allow Programmatic access: This allows the user to access resources programmatically with a secure key rather than having to enter a password.
    4. elect \"attach policies directly\" and search for \"AWSElasticDisasterRecoveryAgentInstallationPolicy\".
    5. Create user.

    To create Failback Agent User, Follow the steps above with these two modifications:
    1. Name the user \"FailbackAgentuser\".
    2. Apply the \"AWSElasticDisasterRecoveryFailbackInstallationPolicy\".
  "
  desc  'fix', "
    Grant the replication agent a role, not a long-lived user with an access key.

    1. Where the source server is an EC2 instance, attach an instance profile
       carrying the AWS-managed policy for Elastic Disaster Recovery agent
       installation. The agent then obtains short-lived credentials from the instance
       metadata service and nothing needs storing on disk.
    2. For source servers outside AWS, where a key is unavoidable, create a dedicated
       IAM user with only that managed policy, no console access, and a documented
       rotation schedule. Treat the key as a credential of record and monitor its use
       in CloudTrail.
    3. Do not reuse the agent identity for anything else, and do not attach
       administrative policies to it. The installer needs a narrow, specific
       permission set.
    4. Review the identity after installation completes - the permissions needed to
       install are broader than the permissions needed to run.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-001682', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '6.5'
  tag cis_rid:               '6.5'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0605r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

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
  # override else attestation_uri(:boundary, 'C-6.5'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_5_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.5') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure proper IAM configuration for AWS Elastic Disaster Recovery (attestation-required)' do
      skip "attestation-required: 'Ensure proper IAM configuration for AWS Elastic Disaster Recovery' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_5_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.5 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end