# encoding: UTF-8

control 'C-5.1' do
  title 'Amazon Simple Storage Service'
  desc  "
    Amazon Simple Storage Service (Amazon S3) is an object storage service that provides industry-leading scalability, data availability, security, and performance. It allows customers of all sizes and industries to store and protect any amount of data for virtually any use case, including data lakes, cloud-native applications, and mobile apps. With cost-effective storage classes and intuitive management features, you can optimize costs, organize data, and configure precise access controls to meet your specific business, organizational, and compliance requirements.

    By utilizing S3, businesses of all sizes can efficiently store and protect large amounts of data, ensuring it is accessible when needed. The service's cost-effective storage classes and user-friendly management features help optimize costs and streamline data organization. Additionally, S3's fine-tuned access controls allow organizations to meet specific business, organizational, and compliance requirements, enhancing overall data management and security.
  "
  desc  'rationale', "
    Amazon Simple Storage Service (Amazon S3) is an object storage service that provides industry-leading scalability, data availability, security, and performance. It allows customers of all sizes and industries to store and protect any amount of data for virtually any use case, including data lakes, cloud-native applications, and mobile apps. With cost-effective storage classes and intuitive management features, you can optimize costs, organize data, and configure precise access controls to meet your specific business, organizational, and compliance requirements.

    By utilizing S3, businesses of all sizes can efficiently store and protect large amounts of data, ensuring it is accessible when needed. The service's cost-effective storage classes and user-friendly management features help optimize costs and streamline data organization. Additionally, S3's fine-tuned access controls allow organizations to meet specific business, organizational, and compliance requirements, enhancing overall data management and security.
  "
  desc  'check', "
    How Amazon S3 works:
    1. To store your data in Amazon S3, you first create a bucket and specify a bucket name and 
    AWS Region. Then, you upload your data to that bucket as objects in Amazon S3. Each 
    object has a key (or key name), which is the unique identifier for the object within the 
    bucket.
    2. S3 provides features that you can configure to support your specific use case. For 
    example, you can use S3 Versioning to keep multiple versions of an object in the same 
    bucket, which allows you to restore objects that are accidentally deleted or overwritten. 
    Buckets and the objects in them are private and can be accessed only if you explicitly 
    grant access permissions. You can use bucket policies, AWS Identity and Access 
    Management (IAM) policies, access control lists (ACLs), and S3 Access Points to manage 
    access.
  "
  desc  'fix', "
    Set the bucket-level protections that every other S3 control depends on.

        ```
        aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
        aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled
        aws s3api put-bucket-ownership-controls --bucket <bucket-name> --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
        ```

    `BucketOwnerEnforced` disables ACLs entirely, so access is decided by policy
    alone and an object cannot be made public by the account that wrote it. Add a
    bucket policy denying requests where `aws:SecureTransport` is false, and enable
    default encryption with a KMS key.

    Where public access must genuinely be blocked account-wide, set the same block
    at the account level so a new bucket cannot opt out.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AU-4', 'SI-4 (5)', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001848', 'CCI-002663', 'CCI-000051']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0501r1_rule'
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
      it { should have_default_encryption_enabled }
    end
  end
end