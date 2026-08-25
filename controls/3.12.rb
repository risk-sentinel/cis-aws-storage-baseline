# encoding: UTF-8

control 'C-3.12' do
  title 'Ensure configuring IAM for AWS Elastic Disaster Recovery'
  desc  "
    Before installing the AWS Elastic Disaster Recovery client, you need to configure AWS IAM permissions and users for both the AWS Replication and AWS Failback Client.

    Configuring AWS IAM permissions and users before installing the AWS Elastic Disaster Recovery client ensures that the AWS Replication and AWS Failback Client have the necessary access rights. This setup is essential for maintaining security and preventing unauthorized access. Proper IAM configuration guarantees the smooth operation of disaster recovery processes, safeguarding your data and ensuring system reliability.
  "
  desc  'rationale', "
    Before installing the AWS Elastic Disaster Recovery client, you need to configure AWS IAM permissions and users for both the AWS Replication and AWS Failback Client.

    Configuring AWS IAM permissions and users before installing the AWS Elastic Disaster Recovery client ensures that the AWS Replication and AWS Failback Client have the necessary access rights. This setup is essential for maintaining security and preventing unauthorized access. Proper IAM configuration guarantees the smooth operation of disaster recovery processes, safeguarding your data and ensuring system reliability.
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
    Configure IAM Credentials for AWS Elastic Disaster Recovery.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.12'
  tag cis_rid:               '3.12'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0312r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.12'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_3_12_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.12') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure configuring IAM for AWS Elastic Disaster Recovery (attestation-required)' do
      skip "attestation-required: 'Ensure configuring IAM for AWS Elastic Disaster Recovery' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_12_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.12 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end