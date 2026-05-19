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
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0408r1_rule'
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

  describe 'Ensure exporting cache to S3' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0408r1_rule.'
  end
end
