# encoding: UTF-8

control 'C-3.7' do
  title 'Ensure File-Level Access Control with Mount Targets'
  desc  "
    Mount targets act as gateways, enabling resources to be accessed across different availability zones within a VPC. When you create an EFS file system, mount targets are automatically provisioned in each availability zone associated with the VPC. This ensures high availability and redundancy, allowing seamless and efficient access to the EFS file system from any availability zone.

    Using mount targets ensures seamless access to the EFS file system across different availability zones within a VPC. This automatic provisioning of mount targets in each availability zone provides high availability and redundancy, essential for maintaining uninterrupted data access. It simplifies configuration and enhances the resilience and scalability of the file system architecture.
  "
  desc  'rationale', "
    Mount targets act as gateways, enabling resources to be accessed across different availability zones within a VPC. When you create an EFS file system, mount targets are automatically provisioned in each availability zone associated with the VPC. This ensures high availability and redundancy, allowing seamless and efficient access to the EFS file system from any availability zone.

    Using mount targets ensures seamless access to the EFS file system across different availability zones within a VPC. This automatic provisioning of mount targets in each availability zone provides high availability and redundancy, essential for maintaining uninterrupted data access. It simplifies configuration and enhances the resilience and scalability of the file system architecture.
  "
  desc  'check', "
    This control is satisfied by a documented evidence record rather than by an API
    assertion, so the profile checks that the record exists and is current rather
    than inspecting live configuration.

    Point `boundary_docs_base` (or the per-control attestation input) at the
    evidence record, then confirm the record shows:

    - the access points defined for each file system, with the POSIX user, group and
      root directory each pins its application to;
    - the file system policy, including that it requires IAM authentication and
      denies requests where `aws:SecureTransport` is false;
    - that clients mount with the `iam` and `tls` options;
    - the date of the most recent review.

    The control fails if the record is missing, unreachable, or older than
    `attestation_max_age_days`.
  "
  desc  'fix', "
    Control access by modifying mount targets in each availability zone.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.7'
  tag cis_rid:               '3.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0307r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.7'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_3_7_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.7') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure File-Level Access Control with Mount Targets (attestation-required)' do
      skip "attestation-required: 'Ensure File-Level Access Control with Mount Targets' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_7_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.7 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end