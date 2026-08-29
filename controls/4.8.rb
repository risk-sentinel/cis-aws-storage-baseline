# encoding: UTF-8

control 'C-4.8' do
  title 'Ensure exporting cache to S3'
  desc  "
    The S3 bucket we created earlier will store the files generated at this mount point.

    The rationale behind using the S3 bucket to store files generated at the mount point is to ensure scalable, durable, and cost-effective storage for your data. By exporting files to S3, you benefit from its high availability and robust data management features, which enhances data security and accessibility. This approach also optimizes storage resource utilization and simplifies data backup and retrieval processes.
  "
  desc  'rationale', "
    The S3 bucket we created earlier will store the files generated at this mount point.

    The rationale behind using the S3 bucket to store files generated at the mount point is to ensure scalable, durable, and cost-effective storage for your data. By exporting files to S3, you benefit from its high availability and robust data management features, which enhances data security and accessibility. This approach also optimizes storage resource utilization and simplifies data backup and retrieval processes.
  "
  desc  'check', "
    We can export the files that were created to the S3 bucket using the following steps:
    1. Create a file on the FSx mount point:
    2. Run the command: 
    ```
    sudo touch efx.txt
    ```
    3. Now run the command: 
    ```
    sudo lsm hsm_archive efx.txt
    ```
    4. Now check your S3 bucket that was created earlier.
  "
  desc  'fix', "
    Data leaving the cache lands in S3 and inherits that bucket's posture, so the
    export path is where the control applies.

    1. Confirm the linked bucket has default encryption, Block Public Access and
       versioning enabled before archiving anything to it.
    2. Archive through the HSM interface and verify the object appears with the
       expected encryption:

        ```
        sudo lfs hsm_archive <file>
        aws s3api head-object --bucket <bucket-name> --key <key>
        ```

    3. Enable a CloudTrail data event trail on the bucket so reads of exported data
       are attributable.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0408r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.8'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_4_8_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.8') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure exporting cache to S3 (attestation-required)' do
      skip "attestation-required: 'Ensure exporting cache to S3' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_8_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.8 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end