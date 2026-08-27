# encoding: UTF-8

control 'C-3.5' do
  title 'Ensure using Security Groups for VPC'
  desc  "
    A security group controls the traffic that is allowed to reach and leave the resources that it is associated with. For example, after you associate a security group with an EC2 instance, it controls the inbound and outbound traffic for the instance.
  "
  desc  'rationale', "
    A security group controls the traffic that is allowed to reach and leave the resources that it is associated with. For example, after you associate a security group with an EC2 instance, it controls the inbound and outbound traffic for the instance.
  "
  desc  'check', "
    1. Go to https://console.aws.amazon.com/vpc/
    2. Navigate to Security Groups and select on the VPC that houses your mount target.
    3. Ensure that incoming traffic is restricted to SSH access on port 22 using TCP protocol and outbound traffic is accepting all traffic.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AC-17 (1)']
  tag cci:                   ['CCI-001682', 'CCI-000067']
  tag cis_number:            '3.5'
  tag cis_rid:               '3.5'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0305r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.5'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_3_5_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.5') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure using Security Groups for VPC (attestation-required)' do
      skip "attestation-required: 'Ensure using Security Groups for VPC' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_5_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.5 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end