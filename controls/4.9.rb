# encoding: UTF-8

control 'C-4.9' do
  title 'Ensure cleaning up FSx Resources'
  desc  "
    Cleaning up FSx resources involves removing unused or unnecessary FSx file systems and associated components to optimize costs and maintain a secure cloud environment. This includes deleting redundant file systems, snapshots, and mount targets, while ensuring all data is backed up or migrated. Regular cleanup prevents resource sprawl, reduces expenses, and maintains the overall health and performance of your AWS infrastructure.

    The rationale for cleaning up FSx resources is to optimize costs and ensure a secure and efficient cloud environment. By removing unused or unnecessary file systems, snapshots, and mount targets, you prevent resource sprawl and reduce unnecessary expenses. Regular cleanup also helps maintain the overall health and performance of your AWS infrastructure, ensuring it remains organized and secure.
  "
  desc  'rationale', "
    Cleaning up FSx resources involves removing unused or unnecessary FSx file systems and associated components to optimize costs and maintain a secure cloud environment. This includes deleting redundant file systems, snapshots, and mount targets, while ensuring all data is backed up or migrated. Regular cleanup prevents resource sprawl, reduces expenses, and maintains the overall health and performance of your AWS infrastructure.

    The rationale for cleaning up FSx resources is to optimize costs and ensure a secure and efficient cloud environment. By removing unused or unnecessary file systems, snapshots, and mount targets, you prevent resource sprawl and reduce unnecessary expenses. Regular cleanup also helps maintain the overall health and performance of your AWS infrastructure, ensuring it remains organized and secure.
  "
  desc  'check', "
    To clean the FSx resources -
    1. Terminate the EC2 instance.
    2. Delete Fsx cache - On the actions drop down, select delete cache.
    3. Verify that you want to delete the service.
    4. Select ```Delete```. It will take some time to delete the cache.
    5. Delete the S3 Bucket
    Before you can delete the bucket you must first empty the bucket. Check the radio box and select ```Empty```
    Select the bucket that you want to delete and select ```Delete ```n the S3 console.
  "
  desc  'fix', "
    Decommissioning is where data is most often left behind. Remove the resources in
    dependency order and confirm the data is actually gone.

    1. Export or archive anything still needed, then unmount the cache from every
       client.
    2. Delete the file cache, and confirm its status reaches DELETED rather than
       assuming the request succeeded.
    3. Empty and delete the linked S3 bucket only after confirming no other workload
       reads it. If versioning is enabled, delete the noncurrent versions and delete
       markers too - emptying a versioned bucket through the console leaves them.
    4. Terminate the client instances and delete the EBS volumes that did not have
       `DeleteOnTermination` set.
    5. Remove the IAM roles, security groups and KMS key grants created for the
       cache, so no orphaned permission remains pointing at a resource that no
       longer exists.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-4', 'AU-4', 'SI-4 (5)']
  tag ksi:                   ['KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-INR-RIR', 'KSI-MLA-LET', 'KSI-MLA-OSM']
  tag nist_r4:               ['AC-4', 'AU-4', 'SI-4 (5)']
  tag cci:                   ['CCI-001548', 'CCI-001848', 'CCI-002663']
  tag cis_number:            '4.9'
  tag cis_rid:               '4.9'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0409r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.9'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_4_9_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.9') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure cleaning up FSx Resources (attestation-required)' do
      skip "attestation-required: 'Ensure cleaning up FSx Resources' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_9_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.9 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end