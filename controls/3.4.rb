# encoding: UTF-8

control 'C-3.4' do
  title 'Ensure controlling Network access to EFS Services'
  desc  "
    It's important that you secure access to your resources on your AWS VPC network. There are several ways to ensure that you control what traffic is accessing your resources. Some of which include tightening down network layer security using a Security Group and a NACL within the VPC console. You can also tighten down Security Groups within your EC2 console and by using AWS IAM. Maintaining network security is a high priority to ensure that no unauthorized users can access the data stored on your EFS service.

    Maintaining network security is a best practice essential for keeping your data safe and secure.
  "
  desc  'rationale', "
    It's important that you secure access to your resources on your AWS VPC network. There are several ways to ensure that you control what traffic is accessing your resources. Some of which include tightening down network layer security using a Security Group and a NACL within the VPC console. You can also tighten down Security Groups within your EC2 console and by using AWS IAM. Maintaining network security is a high priority to ensure that no unauthorized users can access the data stored on your EFS service.

    Maintaining network security is a best practice essential for keeping your data safe and secure.
  "
  desc  'check', "
    This control is satisfied by a documented evidence record rather than by an API
    assertion, so the profile checks that the record exists and is current rather
    than inspecting live configuration.

    Point `boundary_docs_base` (or the per-control attestation input) at the
    evidence record, then confirm the record shows:

    - which EFS file systems are in scope and the network path to each;
    - the mount target security groups, and that inbound is limited to TCP 2049 from
      named client security groups;
    - that no mount target is reachable from a public subnet or an unrestricted
      CIDR;
    - the date of the most recent review.

    The control fails if the record is missing, unreachable, or older than
    `attestation_max_age_days`.
  "
  desc  'fix', "
    Implement network security access controls.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'SI-4 (5)', 'AC-17 (2)']
  tag cci:                   ['CCI-000213', 'CCI-002663', 'CCI-000068']
  tag cis_number:            '3.4'
  tag cis_rid:               '3.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0304r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.4'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_3_4_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.4') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure controlling Network access to EFS Services (attestation-required)' do
      skip "attestation-required: 'Ensure controlling Network access to EFS Services' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_4_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.4 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end