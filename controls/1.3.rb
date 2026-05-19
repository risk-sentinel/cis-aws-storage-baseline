# encoding: UTF-8

control 'C-1.3' do
  title 'Ensure to create backup template and name'
  desc  "
    To create a backup plan, select a template and specify a name for the plan. Additionally, define 
    backup rules according to your requirements and then click on create backup option.
  "
  desc  'rationale', "
    To create a backup plan, select a template and specify a name for the plan. Additionally, define 
    backup rules according to your requirements and then click on create backup option.
  "
  desc  'check', "
    Backup Resources:

    Once you've made your backup plan, it's time to put it into action and start backing up your stuff. 
    Let's start by backing up an S3 storage bucket.

    To back up Elastic Beanstalk instance stored on AWS S3, we'll need to tag its Amazon 
    Resource Name (ARN) with a backup plan. In S3, go to \"properties\" to attach the backup plan to 
    the resource:
    1. Copy the ARN from the console:
    From the AWS Management Console, copy the ARN (Amazon Resource Name) associated with the
    Elastic Beanstalk instance. This unique identifier will be used to tag the resource for backup.
    2. Assign the resource:
    	- After copying the ARN, return to the AWS Management Console and access Amazon 
    Backup.
    	- Choose the backup plan recently created, then proceed to assign the resource you wish to 
    backup, such as the S3 bucket containing the Elastic Beanstalk resource.
    	- Finally, navigate to \"Resource Assignments\" to complete the process.
    Choose \"Assign Resources\" and provide a name for the assignment. For now, maintain the role as 
    Default. In subsequent sections, we'll explore implementing custom IAM roles and policies for your
    backup operations.
    Select the resource(s) that you want to backup. You have the option to backup all your resources, 
    but we're just going to back up the specific Elastic Beanstalk resource for now.
    The resources are now being backed up according to the schedule established by your organization.
  "
  desc  'fix', "
    The AWS backup vault serves as the storage location for your backups. It's crucial to manage access
    to these backups to prevent unauthorized access and ensure data security.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '1.3'
  tag cis_rid:               '1.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0103r1_rule'
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

  describe 'Ensure to create backup template and name' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0103r1_rule.'
  end
end
