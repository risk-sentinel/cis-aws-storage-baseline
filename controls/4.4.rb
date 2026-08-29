# encoding: UTF-8

control 'C-4.4' do
  title 'Ensure the creation of Elastic File Cache'
  desc  "
    With the prerequisites completed, we can now proceed to create our Elastic File Cache.

    By implementing an Elastic File Cache, frequently accessed data is stored closer to the application, reducing latency and speeding up access times. This approach optimizes resource utilization, improves user experience, and ensures that the system can handle high-demand workloads effectively.
  "
  desc  'rationale', "
    With the prerequisites completed, we can now proceed to create our Elastic File Cache.

    By implementing an Elastic File Cache, frequently accessed data is stored closer to the application, reducing latency and speeding up access times. This approach optimizes resource utilization, improves user experience, and ensures that the system can handle high-demand workloads effectively.
  "
  desc  'check', "
    1. Navigate to the AWS Elastic File Cache console: https://console.aws.amazon.com/fsx/.
    2. Click the hamburger menu on the left side of the screen and select \"caches\".
    3. Select \"Create Cache\"
    4. Give your Cache a name. Choose a name that you will remember.
    5. Select the amount of storage capacity you need for your cache. We'll select 1.2 TiB for this tutorial. You can select storage capacity in increments of 1.2 TiB. 
    6. Select the amount of throughput capacity. The amount of Throughput capacity is calculated by multiplying the cache storage capacity by the throughput tier. For example, for a 1.2 TiB cache, it's 1200 MB/s; for a 9.6 TiB cache, it's 9600 MB/s. Throughput capacity is the sustained speed at which the file server that hosts your cache can serve data. 
    7. In the Network & Security section, provide networking and security group information:
    	- For Virtual Private Cloud (VPC) choose the correct amazon VPC that you want to associate with your cache. We're going to use the default VPC.
    	- For VPC Security Groups, the ID for the default security group for your VPC should already be added.
    	- For Subnet, you can choose any of the available subnets.
    8. In the Encryption section, choose the Default aws/fsx KMS encryption keys to protect your data by encrypting your data at-rest. 
    9. You have the option to create tags; this is an optional step. 
    10. Select \"next\".
    11. In the Data repository associations (DRAs) section, there are no DRAs linking your cache to S3 or NFS repositories. We need to link the cache that we're creating to the Amazon S3 bucket that we created earlier. 
    	- For Data repository type, choose S3
    	- For Data repository path, type the path of the S3 bucket that you want to associate with this cache. For example: 
    ```
    s3://{example-bucket}/{example-prefix}
    ```	     	- To access this URL, go back to the S3 bucket that was just created and navigate to the directory of the folder that you created. Select \"copy AWS URI\".
    	- For cache path, enter the name of a high-level directory such as /ns1 or subdirectory such as ns1/subdir within Amazon File Cache to associate with the S3 data repository. The first forward slash in the path is required. 
    12. Select \"next\" this will take you to the summary page.
    13. Choose\" Create Cache.\" You will see your cache in the FSx dashboard.
  "
  desc  'fix', "
    1. Create the cache in a private subnet, with no route to an internet gateway.
    2. Enable encryption at rest using a customer-managed KMS key, and record the
       key so its rotation and access policy can be audited.
    3. Attach a security group permitting Lustre traffic only from the client
       security group, not from a CIDR range.
    4. Link the cache to the S3 data repository over the VPC rather than the public
       endpoint, using an S3 gateway endpoint on the subnet's route table.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0404r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.4'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_4_4_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.4') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure the creation of Elastic File Cache (attestation-required)' do
      skip "attestation-required: 'Ensure the creation of Elastic File Cache' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_4_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.4 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end