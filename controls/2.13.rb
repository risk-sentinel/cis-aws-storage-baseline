# encoding: UTF-8

control 'C-2.13' do
  title 'Ensure creating an SNS subscription'
  desc  "
    Create an SNS notification to send to the system administrator's email address.
  "
  desc  'rationale', "
    Create an SNS notification to send to the system administrator's email address.
  "
  desc  'check', "
    Creating an SNS subscription:
    1. Navigate to SNS service in the AWS console - https://us-east-2.console.aws.amazon.com/sns/v3/home?region=us-east-2#/homepage (make sure you are in the correct region).
    2. Navigate to \"topics\".
    3. Create a new topic.
    4. Select the ARN of the topic.
    5. Select the \"Email\" protocol if you wish to have the alarms delivered to your email.
    6. Enter the correct email address of an administrator.
    7. Select \"Create Subscription\".

    To attach the SNS notification service to the alarm - select the SNS subscription that you just created and create the alarm.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.13'
  tag cis_rid:               '2.13'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0213r1_rule'
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

  describe 'Ensure creating an SNS subscription' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0213r1_rule.'
  end
end
