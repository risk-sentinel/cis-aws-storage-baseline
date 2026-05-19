# encoding: UTF-8

control 'C-6.8' do
  title 'Ensure execution of a recovery drill'
  desc  "
    To ensure your organization is prepared for a disaster, it's crucial to verify that your disaster recovery services function as expected. Your IT team should conduct regular recovery drills on your AWS Elastic Recovery Instance to confirm everything operates smoothly and according to plan.

    Regular recovery drills are essential to verify the functionality of your disaster recovery services and ensure your organization is well-prepared for any disruptions. By conducting these drills on your AWS Elastic Recovery Instance, you can identify and address potential issues before they impact operations. This proactive approach enhances the reliability and effectiveness of your disaster recovery plan, providing confidence that your systems can recover swiftly and efficiently in the event of a disaster.
  "
  desc  'rationale', "
    To ensure your organization is prepared for a disaster, it's crucial to verify that your disaster recovery services function as expected. Your IT team should conduct regular recovery drills on your AWS Elastic Recovery Instance to confirm everything operates smoothly and according to plan.

    Regular recovery drills are essential to verify the functionality of your disaster recovery services and ensure your organization is well-prepared for any disruptions. By conducting these drills on your AWS Elastic Recovery Instance, you can identify and address potential issues before they impact operations. This proactive approach enhances the reliability and effectiveness of your disaster recovery plan, providing confidence that your systems can recover swiftly and efficiently in the event of a disaster.
  "
  desc  'check', "
    Steps to perform a recovery drill:
    1. Navigate to source servers tab in AWS Elastic Disaster Recovery Dashboard.
    2. Make sure that all servers you launch show as \"Ready\" under \"status,\" report as \"healthy\" in the data replication status column, and that pending actions show as \"initiate drill\".
    3. Select \"initiate drill\" under the orange dropdown menu. Make sure that you don't initiate a real recovery job. 
    4. Choose a recovery point. Normally, it makes sense to choose the most recent recovery point, but you can also choose a recovery point from earlier.
    5. Select the orange \"initiate drill\" to initiate the recovery drill.
    6. To complete the recovery drill, clean up your resources by deleting the recovery instance by selecting actions and \"terminate recovery instances\".
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['MP-7 (a)', 'CP-4 a', 'IR-3']
  tag cci:                   ['CCI-002581', 'CCI-000490', 'CCI-000818']
  tag cis_number:            '6.8'
  tag cis_rid:               '6.8'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0608r1_rule'
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

  describe 'Ensure execution of a recovery drill' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0608r1_rule.'
  end
end
