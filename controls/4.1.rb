# encoding: UTF-8

control 'C-4.1' do
  title 'FSX (AWS Elastic File Cache)'
  desc  "
    Amazon File Cache is a fully managed, high speed cache on AWS that is used to process file data, regardless of where the data is stored. AWS File Cache is a serverless service on AWS that spares the administrators from the burden of managing file servers and storage volumes, updating hardware, configuring software, running out of capacity, or tuning performance. AWS Elastic cache is capable of handling hundreds of GB/s of throughput and up to millions of operations per second. AWS FSx is an excellent service for cost optimization and high scalability. Amazon File Cache automatically loads data into the cache when it's accessed for the first time and automatically releases data when it's not used.

    Amazon File Cache is used as a temporary, high performance storage location for data that's stored in on-premises file systems, AWS file systems, and Amazon S3 buckets. This service is used for data processing and is best suited for applications that need high data processing speeds. This is not a long term storage option.
  "
  desc  'rationale', "
    Amazon File Cache is a fully managed, high speed cache on AWS that is used to process file data, regardless of where the data is stored. AWS File Cache is a serverless service on AWS that spares the administrators from the burden of managing file servers and storage volumes, updating hardware, configuring software, running out of capacity, or tuning performance. AWS Elastic cache is capable of handling hundreds of GB/s of throughput and up to millions of operations per second. AWS FSx is an excellent service for cost optimization and high scalability. Amazon File Cache automatically loads data into the cache when it's accessed for the first time and automatically releases data when it's not used.

    Amazon File Cache is used as a temporary, high performance storage location for data that's stored in on-premises file systems, AWS file systems, and Amazon S3 buckets. This service is used for data processing and is best suited for applications that need high data processing speeds. This is not a long term storage option.
  "
  desc  'check', "
    This control is satisfied by a documented evidence record rather than by an API
    assertion, so the profile checks that the record exists and is current rather
    than inspecting live configuration.

    Point `boundary_docs_base` (or the per-control attestation input) at the
    evidence record, then confirm the record shows:

    - the file caches in scope, the subnet each sits in, and that none is in a
      public subnet;
    - encryption at rest and the KMS key used;
    - the security groups permitting Lustre traffic, and the client groups they
      reference;
    - the linked S3 data repository and its public-access, encryption and versioning
      posture.

    The control fails if the record is missing, unreachable, or older than
    `attestation_max_age_days`.
  "
  desc  'fix', "
    You can link your cache to S3 data repositories or to any file system that supports the NFSv3 protocol. The NFS data repository can either be on premises or in the cloud and you can link a maximum of eight repositories. All the linked repositories must be using the same file system; either S3 or NFS. When linked to a data repository, Amazon File Cache transparently presents S3 or NFS objects as files and directories. 
    Amazon File Cache is compatible to be used interchangeably with Amazon Elastic Compute Service, Amazon Elastic Container Service, and Amazon Elastic Kubernetes Service.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AU-4', 'SI-4 (5)', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001848', 'CCI-002663', 'CCI-000051']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0401r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.1'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_4_1_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.1') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'FSX (AWS Elastic File Cache) (attestation-required)' do
      skip "attestation-required: 'FSX (AWS Elastic File Cache)' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_1_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.1 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end