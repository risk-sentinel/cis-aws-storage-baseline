# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure Storage Classes are Configured'
  desc  "
    Amazon S3 offers various storage classes to optimize cost and performance based on data access patterns and retention needs. Standard Storage is for frequently accessed data, while Standard-IA and One Zone-IA are for infrequent access, with the latter offering cost savings by storing in a single Availability Zone. Intelligent-Tiering automatically moves data between access tiers based on usage, and Glacier and Glacier Deep Archive provide low-cost options for long-term archival storage with varying retrieval times. Each class balances availability, durability, performance, and cost, enabling a tailored storage strategy to meet specific requirements.

    This approach ensures frequently accessed data is readily available, while infrequently accessed data is stored cost-effectively, balancing availability, durability, and cost.
  "
  desc  'rationale', "
    Amazon S3 offers various storage classes to optimize cost and performance based on data access patterns and retention needs. Standard Storage is for frequently accessed data, while Standard-IA and One Zone-IA are for infrequent access, with the latter offering cost savings by storing in a single Availability Zone. Intelligent-Tiering automatically moves data between access tiers based on usage, and Glacier and Glacier Deep Archive provide low-cost options for long-term archival storage with varying retrieval times. Each class balances availability, durability, performance, and cost, enabling a tailored storage strategy to meet specific requirements.

    This approach ensures frequently accessed data is readily available, while infrequently accessed data is stored cost-effectively, balancing availability, durability, and cost.
  "
  desc  'check', "
    TODO: check content missing in source XCCDF
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AU-4', 'SI-4 (5)']
  tag cci:                   ['CCI-000213', 'CCI-001848', 'CCI-002663']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0503r1_rule'
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

  describe 'Ensure Storage Classes are Configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0503r1_rule.'
  end
end
