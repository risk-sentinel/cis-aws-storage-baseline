# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure the creation of an FSX Bucket'
  desc  "
    An S3 bucket will store the data that Amazon Elastic File Cache accesses

    Storing data in S3 ensures scalability, durability, and cost-efficiency, while Amazon Elastic File Cache enhances access speed by caching frequently accessed data. This combination leverages the strengths of both services, providing a seamless and efficient data storage and retrieval solution.
  "
  desc  'rationale', "
    An S3 bucket will store the data that Amazon Elastic File Cache accesses

    Storing data in S3 ensures scalability, durability, and cost-efficiency, while Amazon Elastic File Cache enhances access speed by caching frequently accessed data. This combination leverages the strengths of both services, providing a seamless and efficient data storage and retrieval solution.
  "
  desc  'check', "
    1. Navigate to the Amazon S3 bucket console. https://s3.console.aws.amazon.com/s3/.
    2. Select \"Create Bucket\".
    3. Give your bucket a name and select the region. Note: your bucket must be a unique name that's not used anywhere else on AWS.
    4. Block public access: This is an internal service that will not be accessed outside of our internal AWS network. Keep the \"block public access\" setting checked.
    5. Enable bucket versioning.
    6. Leave the rest of the settings as default.
    7. Select \"create bucket.\"
    8. Create a path in your bucket, give it a name and leave the encryption as default for now.
  "
  desc  'fix', "
    Create the linked bucket with its protections on from the start, since data is
    exported into it automatically.

        ```
        aws s3api create-bucket --bucket <bucket-name> --region <region>
        aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
        aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled
        aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"<kms-key-arn>\"},\"BucketKeyEnabled\":true}]}'
        ```

    Add a bucket policy denying requests where `aws:SecureTransport` is false, and
    enable server access logging or a CloudTrail data event trail so reads of the
    exported data are recorded.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-2 (2)', 'AU-4', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001682', 'CCI-001848', 'CCI-000051']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0403r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.3'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_4_3_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.3') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure the creation of an FSX Bucket (attestation-required)' do
      skip "attestation-required: 'Ensure the creation of an FSX Bucket' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_3_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.3 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end