# encoding: UTF-8

control 'C-5.2' do
  title 'Ensure direct data addition to S3'
  desc  "
    Your bucket name must be unique and not already in use on AWS. Click on your bucket name, and in the right corner, you will find an option to upload data directly to your S3 bucket. You can choose the file option to upload individual files, images, or even entire folders.

    Accessing the upload option within your bucket simplifies the process of adding data, making it easy to manage and organize your files. This streamlined approach allows for efficient data storage, retrieval, and management within the AWS S3 environment, enhancing overall operational efficiency.
  "
  desc  'rationale', "
    Your bucket name must be unique and not already in use on AWS. Click on your bucket name, and in the right corner, you will find an option to upload data directly to your S3 bucket. You can choose the file option to upload individual files, images, or even entire folders.

    Accessing the upload option within your bucket simplifies the process of adding data, making it easy to manage and organize your files. This streamlined approach allows for efficient data storage, retrieval, and management within the AWS S3 environment, enhancing overall operational efficiency.
  "
  desc  'check', "
    Access Point in S3 Bucket:
    Access points are named network endpoints that are attached to buckets which simplify 
    managing data access at scale in S3. To see if any of the access points attached to this 
    bucket grant public or cross-account access, go to IAM Access Analyzer for S3.
    1. Enter a name for the access point. The name must be unique within the AWS 
    account and Region.
    2. Choose the VPC (Virtual Private Cloud) and subnet where you want the access point to be 
    accessible. This determines the network traffic routing for the access point.
    3. Optionally, you can configure additional settings such as permissions, bucket policy, and 
    endpoint policy for the access point.
    4. Review the settings, and click on \"Create access point\" to create the access point
  "
  desc  'fix', "
    Put an access point in front of the bucket so each consumer gets its own
    constrained entry point rather than a shared bucket policy.

        ```
        aws s3control create-access-point --account-id <account-id> --name <access-point-name> --bucket <bucket-name> --vpc-configuration VpcId=<vpc-id>
        ```

    1. Supplying `--vpc-configuration` makes the access point reachable only from
       that VPC, which is what prevents data being pulled from the internet even if
       a credential leaks.
    2. Give each access point a policy granting only the prefixes and actions that
       consumer needs.
    3. Run IAM Access Analyzer for S3 and confirm no access point reports public or
       cross-account access that was not intended.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AU-4', 'SI-4 (5)', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001848', 'CCI-002663', 'CCI-000051']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0502r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  aws_s3_buckets.bucket_names.each do |b|
    describe aws_s3_bucket(b) do
      it { should_not be_public }
    end
  end
end