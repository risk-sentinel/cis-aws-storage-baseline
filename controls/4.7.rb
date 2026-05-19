# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure mounting FSx cache'
  desc  "
    Mounting the FSx cache is a crucial step to optimize data retrieval and system performance. This process involves connecting the FSx file system to your compute instances, allowing them to access cached data efficiently. Properly mounting the FSx cache ensures low-latency access to frequently used data, enhances overall application performance, and leverages the full capabilities of the AWS FSx service. This setup is essential for achieving high performance and efficient data processing in your AWS environment.

    By connecting the FSx file system to your compute instances, you enable low-latency access to frequently used data, significantly improving application performance. This setup leverages the full capabilities of the AWS FSx service, ensuring efficient data processing and resource utilization in your AWS environment. Properly mounting the FSx cache is essential for achieving high performance and operational efficiency.
  "
  desc  'rationale', "
    Mounting the FSx cache is a crucial step to optimize data retrieval and system performance. This process involves connecting the FSx file system to your compute instances, allowing them to access cached data efficiently. Properly mounting the FSx cache ensures low-latency access to frequently used data, enhances overall application performance, and leverages the full capabilities of the AWS FSx service. This setup is essential for achieving high performance and efficient data processing in your AWS environment.

    By connecting the FSx file system to your compute instances, you enable low-latency access to frequently used data, significantly improving application performance. This setup leverages the full capabilities of the AWS FSx service, ensuring efficient data processing and resource utilization in your AWS environment. Properly mounting the FSx cache is essential for achieving high performance and operational efficiency.
  "
  desc  'check', "
    To mount your cache, follow the next steps:
    1. Make a directory for the mount point with the following command:
    ```
    sudo mkdir -p /mnt
    ```
    2. Mount the Amazon file cache to the directory that you just created. Use the following command and replace these names:
    	- Replace cache_dns_name with the actual file cache's Domain Name System (DNS) name
    	- Replace mountname with the cache's mount name, which you can get by running the describe-file-caches AWS CLI command or DescribeFileCaches API operation 
    ```
    sudo mount -t lustre -o relatime,flock cache_dns_name@tcp:/mountname /mnt
    ```
    Note: Make sure your EC2 instance is in the same VPC as your cache.
    If done correctly, the path of your folder will show up in the /mnt folder.

    You can also use the df command to see the DNS and mount point is attached to your file system:
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'IA-5 (1) (e)', 'AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-000213', 'CCI-000200', 'CCI-001682', 'CCI-001848']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0407r1_rule'
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

  describe 'Ensure mounting FSx cache' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0407r1_rule.'
  end
end
