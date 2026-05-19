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
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
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

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe 'Ensure the creation of an FSX Bucket' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0403r1_rule.'
  end
end
