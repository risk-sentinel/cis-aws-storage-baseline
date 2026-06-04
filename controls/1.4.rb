# encoding: UTF-8

control 'C-1.4' do
  title 'Ensure to create AWS IAM Policies'
  desc  "
    AWS IAM policies, specify the desired permissions for accessing AWS resources and define the 
    conditions under which those permissions are granted. Configure the appropriate policies to keep 
    your resources secure.

    Managing AWS IAM policies is crucial to safeguard your backups from unauthorized access, 
    ensuring that only approved users can manipulate or view sensitive data.
  "
  desc  'rationale', "
    AWS IAM policies, specify the desired permissions for accessing AWS resources and define the 
    conditions under which those permissions are granted. Configure the appropriate policies to keep 
    your resources secure.

    Managing AWS IAM policies is crucial to safeguard your backups from unauthorized access, 
    ensuring that only approved users can manipulate or view sensitive data.
  "
  desc  'check', "
    To create a role for AWS Backup, follow these steps:
    1. Navigate to the \"IAM Dashboard\" in the AWS Console.
    2. Select \"Roles\" from the left-hand menu.
    3. Click on the \"Create Role\" button.
    4. Choose \"AWS Service\" as the trusted entity.
    5. Select \"AWS Backup\" as the service that will use this role.
    6. Choose a policy to apply to the role or create a custom policy.
    7. Review the role details and provide a meaningful name for the role.
    8. Click on \"Create Role\" to finalize the creation of the role for AWS Backup.
  "
  desc  'fix', "
    AWS IAM policies, restricting access to backup resources, and implementing additional security 
    measures to prevent future incidents.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.4'
  tag cis_rid:               '1.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0104r1_rule'
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
  # to evidence-class attestation (sparc-validate#154/#8): resolves the per-control
  # override else attestation_uri(:boundary, 'C-1.4'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_1_4_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-1.4') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure to create AWS IAM Policies (attestation-required)' do
      skip "attestation-required: 'Ensure to create AWS IAM Policies' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_1_4_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-1.4 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end