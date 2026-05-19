# encoding: UTF-8

control 'C-3.1' do
  title 'EFS'
  desc  "
    AWS EFS is a scalable and fully-managed storage service that enables you to quickly deploy file systems without the hassle of configuring, patching, or maintaining them.

    Utilize AWS EFS to streamline your file system deployment, allowing the service to handle the heavy lifting for you.
  "
  desc  'rationale', "
    AWS EFS is a scalable and fully-managed storage service that enables you to quickly deploy file systems without the hassle of configuring, patching, or maintaining them.

    Utilize AWS EFS to streamline your file system deployment, allowing the service to handle the heavy lifting for you.
  "
  desc  'check', "
    To create an Amazon EFS (Elastic File System), you can follow these steps:
    1. Sign in to the AWS Management Console and navigate to the Amazon EFS console - https://us-east-2.console.aws.amazon.com/efs?region=us-east-2#/get-started.
    2. Click on the \"Create file system\" button.
    3. Enter a name for your file system.
    4. Choose a VPC for your file system
    5. Then you have to go to File system settings to edit configurations , then you have to select Lifecycle 
    management , performance settings and File system protection , and then click save changes.
  "
  desc  'fix', "
    To create an Amazon EFS (Elastic File System), follow these steps:

    1. Open the Amazon EFS Console: Sign in to your AWS Management Console and navigate to the Amazon EFS service.
    2. Create File System: Click on the \"Create file system\" button to start the creation process.
    3. Configure File System: Select your desired VPC (Virtual Private Cloud) and availability zones for the file system. Optionally, you can configure settings like throughput mode and lifecycle management.
    4. Configure Access Points: Set up access points if needed, to control access permissions and streamline access management.
    5. Review and Create: Review your settings and click on the \"Create\" button to create the file system.
    6. Mount the File System: Once created, use the provided mount targets and instructions to mount the file system to your EC2 instances or other resources.
  "
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'CM-6 a', 'AC-2 c', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-000364', 'CCI-002113', 'CCI-001225']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0301r1_rule'
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

  describe 'EFS' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0301r1_rule.'
  end
end
