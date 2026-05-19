# encoding: UTF-8

control 'C-3.11' do
  title 'Ensure accessing Points and IAM Policies'
  desc  "
    You can use IAM policies to control access to your EFS access points. To achieve this, utilize the `elasticfilesystem:AccessPointArn` IAM condition key. The `AccessPointArn` represents the Amazon Resource Name (ARN) of the access point that the file system is mounted with.

    The rationale for using IAM policies with the `elasticfilesystem:AccessPointArn` condition key is to ensure precise and secure access control to EFS access points. By specifying the access point's ARN, you can restrict interactions to authorized users and resources only, thereby enhancing data security and preventing unauthorized access. This approach maintains the integrity and confidentiality of your data within the AWS environment.
  "
  desc  'rationale', "
    You can use IAM policies to control access to your EFS access points. To achieve this, utilize the `elasticfilesystem:AccessPointArn` IAM condition key. The `AccessPointArn` represents the Amazon Resource Name (ARN) of the access point that the file system is mounted with.

    The rationale for using IAM policies with the `elasticfilesystem:AccessPointArn` condition key is to ensure precise and secure access control to EFS access points. By specifying the access point's ARN, you can restrict interactions to authorized users and resources only, thereby enhancing data security and preventing unauthorized access. This approach maintains the integrity and confidentiality of your data within the AWS environment.
  "
  desc  'check', "
    Below is a same IAM policy copied from the AWS documentation:
    ```
    {
        \"Version\": \"2012-10-17\",
        \"Id\": \"MyFileSystemPolicy\",
        \"Statement\": [
            {
                \"Sid\": \"App1Access\",
                \"Effect\": \"Allow\",
                \"Principal\": { \"AWS\": \"arn:aws:iam::111122223333:role/app1\" },
                \"Action\": [
                    \"elasticfilesystem:ClientMount\",
                    \"elasticfilesystem:ClientWrite\"
                ],
                \"Condition\": {
                    \"StringEquals\": {
                        \"elasticfilesystem:AccessPointArn\":\"arn:aws:elasticfilesystem:us-east-1:222233334444:access-point/fsap-01234567\"
                    }
                }
            },
            {
                \"Sid\": \"App2Access\",
                \"Effect\": \"Allow\",
                \"Principal\": { \"AWS\": \"arn:aws:iam::111122223333:role/app2\" },
                \"Action\": [
                    \"elasticfilesystem:ClientMount\",
                    \"elasticfilesystem:ClientWrite\"
                ],
                \"Condition\": {
                    \"StringEquals\": {
                        \"elasticfilesystem:AccessPointArn\":\"arn:aws:elasticfilesystem:us-east  1:222233334444:access-point/fsap-89abcdef\"
                    }
                }
            }
        ]
    }
    ```
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.11'
  tag cis_rid:               '3.11'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0311r1_rule'
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

  describe 'Ensure accessing Points and IAM Policies' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0311r1_rule.'
  end
end
