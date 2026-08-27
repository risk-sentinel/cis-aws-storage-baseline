# encoding: UTF-8

control 'C-1.2' do
  title 'Ensure securing AWS Backups'
  desc  "
    As an AWS administrator, it's important to know what you're responsible for. You're responsible for 
    keeping things safe in the cloud, which means taking care of the resources and data on AWS. Here's 
    what you need to secure, according to AWS documentation:
    1. Responsible for alert communication with AWS.
    2. Managing access credentials for AWS resources.
    3. Configuring backup plans according to organization policies.
    4. Ensuring backup recovery capability.
    5. Including AWS Backups in the organization's disaster recovery procedures.
    6. Ensuring user awareness and familiarity with AWS Backups platform usage

    AWS will send periodic emails regarding the status of your backups and any service issues. 
    The administrator must address any communicated issues from AWS, such as billing problems or 
    backup inactivity, and take necessary steps to resolve them.
  "
  desc  'rationale', "
    As an AWS administrator, it's important to know what you're responsible for. You're responsible for 
    keeping things safe in the cloud, which means taking care of the resources and data on AWS. Here's 
    what you need to secure, according to AWS documentation:
    1. Responsible for alert communication with AWS.
    2. Managing access credentials for AWS resources.
    3. Configuring backup plans according to organization policies.
    4. Ensuring backup recovery capability.
    5. Including AWS Backups in the organization's disaster recovery procedures.
    6. Ensuring user awareness and familiarity with AWS Backups platform usage

    AWS will send periodic emails regarding the status of your backups and any service issues. 
    The administrator must address any communicated issues from AWS, such as billing problems or 
    backup inactivity, and take necessary steps to resolve them.
  "
  desc  'check', "
    CREATING AN AWS BACKUP:

    Creating an AWS Backup involves selecting the desired data, specifying backup frequency, and 
    choosing storage options. Below we'll walk through how to create and configure an AWS Backup 
    instance.
    1. Sign into AWS Console:
    To sign into the AWS Console 'https://console.aws.amazon.com/billing/home#/', users navigate to the AWS Management Console website and enter 
    their credentials, including their username and password.
    2. Access the AWS Backup Service Dashboard in the AWS Management Console:
    AWS Management Console and type \"Backup\" or navigate through the services menu to find the 
    \"Storage\" category, where AWS Backup is listed.
    3.  Create Backup Plan:
    Choose \"Create backup plan\" from the options provided. You can either create a custom plan 
    tailored to your requirements or option for a per-defined template offered by AWS
  "
  desc  'fix', "
    Harden the vault holding the backups, not just the backup schedule.

    1. Encrypt the vault with a customer-managed KMS key so key access can be
       revoked independently of the backup service.
    2. Apply a vault access policy that denies `backup:DeleteRecoveryPoint` and
       `backup:UpdateRecoveryPointLifecycle` to everyone except a small break-glass
       role, so an operator credential cannot destroy the recovery points.
    3. Enable AWS Backup Vault Lock in compliance mode once retention is settled.
       In compliance mode the retention period cannot be shortened by anyone,
       including the account root, which is what makes the backups ransomware
       resistant.
    4. Copy critical recovery points to a vault in a second account or Region, so
       loss of the primary account does not take the backups with it.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.2'
  tag cis_rid:               '1.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0102r1_rule'
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
  # override else attestation_uri(:boundary, 'C-1.2'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_1_2_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-1.2') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure securing AWS Backups (attestation-required)' do
      skip "attestation-required: 'Ensure securing AWS Backups' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_1_2_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-1.2 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end