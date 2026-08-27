# encoding: UTF-8

control 'C-1.1' do
  title 'AWS Storage Backups'
  desc  "
    AWS Storage Backups is a managed AWS Service that establishes high resiliency to your cloud 
    resources. AWS Storage Backups are like making extra copies of your important stuff on Amazon's 
    computers. It is an excellent strategy to ensure that the data and resources you use remain available 
    in the event of unrecoverable damage or loss to your resources.

    AWS Backups enable you to back 
    up and restore all data lost during the attack,While AWS Storage Backups provide a level of 
    security, there are numerous methods to fortify your backups, ensuring the protection of your data 
    and services.
  "
  desc  'rationale', "
    AWS Storage Backups is a managed AWS Service that establishes high resiliency to your cloud 
    resources. AWS Storage Backups are like making extra copies of your important stuff on Amazon's 
    computers. It is an excellent strategy to ensure that the data and resources you use remain available 
    in the event of unrecoverable damage or loss to your resources.

    AWS Backups enable you to back 
    up and restore all data lost during the attack,While AWS Storage Backups provide a level of 
    security, there are numerous methods to fortify your backups, ensuring the protection of your data 
    and services.
  "
  desc  'check', "
    TODO: check content missing in source XCCDF
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.1'
  tag cis_rid:               '1.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0101r1_rule'
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
  # override else attestation_uri(:boundary, 'C-1.1'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_1_1_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-1.1') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'AWS Storage Backups (attestation-required)' do
      skip "attestation-required: 'AWS Storage Backups' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_1_1_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-1.1 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end