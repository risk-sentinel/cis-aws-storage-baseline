# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure Storage Classes are Configured'
  desc  "
    Amazon S3 offers various storage classes to optimize cost and performance based on data access patterns and retention needs. Standard Storage is for frequently accessed data, while Standard-IA and One Zone-IA are for infrequent access, with the latter offering cost savings by storing in a single Availability Zone. Intelligent-Tiering automatically moves data between access tiers based on usage, and Glacier and Glacier Deep Archive provide low-cost options for long-term archival storage with varying retrieval times. Each class balances availability, durability, performance, and cost, enabling a tailored storage strategy to meet specific requirements.

    This approach ensures frequently accessed data is readily available, while infrequently accessed data is stored cost-effectively, balancing availability, durability, and cost.
  "
  desc  'rationale', "
    Amazon S3 offers various storage classes to optimize cost and performance based on data access patterns and retention needs. Standard Storage is for frequently accessed data, while Standard-IA and One Zone-IA are for infrequent access, with the latter offering cost savings by storing in a single Availability Zone. Intelligent-Tiering automatically moves data between access tiers based on usage, and Glacier and Glacier Deep Archive provide low-cost options for long-term archival storage with varying retrieval times. Each class balances availability, durability, performance, and cost, enabling a tailored storage strategy to meet specific requirements.

    This approach ensures frequently accessed data is readily available, while infrequently accessed data is stored cost-effectively, balancing availability, durability, and cost.
  "
  desc  'check', "
    This control is satisfied by a documented evidence record rather than by an API
    assertion, so the profile checks that the record exists and is current rather
    than inspecting live configuration.

    Point `boundary_docs_base` (or the per-control attestation input) at the
    evidence record, then confirm the record shows:

    - the lifecycle configuration applied to each bucket in scope, including
      transitions between storage classes and the access pattern justifying them;
    - expiry of noncurrent versions and incomplete multipart uploads;
    - where retention is a compliance obligation, that Object Lock is used rather
      than a lifecycle rule, so retention cannot be shortened;
    - the date of the most recent review.

    The control fails if the record is missing, unreachable, or older than
    `attestation_max_age_days`.
  "
  desc  'fix', "
    Apply lifecycle rules so objects move to the right class and expire, rather than
    accumulating in Standard indefinitely.

        ```
        aws s3api put-bucket-lifecycle-configuration --bucket <bucket-name> --lifecycle-configuration file://lifecycle.json
        ```

    1. Transition infrequently read data to Standard-IA or Glacier on a schedule
       matched to how it is actually accessed.
    2. Expire noncurrent versions and incomplete multipart uploads. Without this,
       versioning quietly retains every overwritten object, including data you
       believe you deleted.
    3. Where retention is a compliance requirement rather than a cost decision, use
       Object Lock in compliance mode instead of a lifecycle rule, so retention
       cannot be shortened.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AU-4', 'SI-4 (5)']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-INR-RIR', 'KSI-MLA-LET', 'KSI-MLA-OSM']
  tag nist_r4:               ['AC-3', 'AU-4', 'SI-4 (5)']
  tag cci:                   ['CCI-000213', 'CCI-001848', 'CCI-002663']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0503r1_rule'
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
  # override else attestation_uri(:boundary, 'C-5.3'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_5_3_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-5.3') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure Storage Classes are Configured (attestation-required)' do
      skip "attestation-required: 'Ensure Storage Classes are Configured' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_5_3_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-5.3 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end