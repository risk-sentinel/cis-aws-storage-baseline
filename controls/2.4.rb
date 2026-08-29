# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure the creation of a new volume'
  desc  "
    Leave the root volume unchanged and create a new volume. To ensure the security of the instance and prevent data loss, select \"no\" under the \"delete on termination\" option and encrypt your volume using AWS KMS. A default key is available for encrypting the volume.

    By leaving the root volume unchanged and creating a new volume, you separate critical data from the operating system. Selecting \"no\" for the \"delete on termination\" option ensures that data on the new volume is not automatically deleted when the instance is terminated, protecting against accidental data loss. Encrypting the volume using AWS KMS adds an additional layer of security, safeguarding the data against unauthorized access. The use of a default key for encryption simplifies the process while maintaining strong security measures.
  "
  desc  'rationale', "
    Leave the root volume unchanged and create a new volume. To ensure the security of the instance and prevent data loss, select \"no\" under the \"delete on termination\" option and encrypt your volume using AWS KMS. A default key is available for encrypting the volume.

    By leaving the root volume unchanged and creating a new volume, you separate critical data from the operating system. Selecting \"no\" for the \"delete on termination\" option ensures that data on the new volume is not automatically deleted when the instance is terminated, protecting against accidental data loss. Encrypting the volume using AWS KMS adds an additional layer of security, safeguarding the data against unauthorized access. The use of a default key for encryption simplifies the process while maintaining strong security measures.
  "
  desc  'check', "
    To audit this configuration in AWS, follow these steps:

    1. Access the AWS Management Console: Log in to your AWS account and navigate to the AWS Management Console.

    2. Review EBS Volumes:
       - Go to the EC2 Dashboard and select \"Volumes\" under the \"Elastic Block Store\" section.
       - Check the properties of each volume to ensure that the root volume is unchanged and new volumes are created as needed.

    3. Check \"Delete on Termination\" Setting:
       - In the \"Volumes\" section, select each volume and click on the \"Actions\" button.
       - Select \"Modify Volume\" and ensure that \"Delete on Termination\" is set to \"no\" for the critical volumes.
       - Alternatively, go to the \"Instances\" section, select an instance, click on the \"Actions\" button, choose \"Instance Settings,\" and then \"Change Termination Protection.\"

    4. Verify Encryption:
       - In the \"Volumes\" section, check the \"Encrypted\" column to confirm that the volumes are encrypted.
       - For detailed information, select a volume and view its details to ensure it is encrypted using AWS KMS.

    5. Review IAM Policies:
       - Navigate to the IAM Dashboard and review the policies attached to users, groups, and roles to ensure they have appropriate permissions to create, modify, and encrypt EBS volumes.

    6. Use AWS Config:
       - Enable AWS Config to continuously monitor and record AWS resource configurations.
       - Create AWS Config rules to check for compliance with best practices, such as ensuring volumes are encrypted and \"Delete on Termination\" is set to \"no.\"

    7. Generate Reports:
       - Use AWS CloudTrail to review logs of API calls made to EBS volumes, ensuring compliance with the required configurations.
       - Generate compliance reports using AWS Config and AWS CloudTrail to provide evidence of adherence to best practices.

    By following these steps, you can effectively audit your EBS configurations to ensure data security, integrity, and operational reliability.
  "
  desc  'fix', "
    1. Volume Configurations:
       - After configuring your volume, ensure the settings meet your requirements. To secure your file system and prevent data loss, verify that the \"Delete on Termination\" option is set to \"no,\" the volume is encrypted, and the KMS key is correctly specified. For this EBS instance, we are using the default KMS key.

    2. Availability Zone Consistency:
       - Ensure your EBS volume is in the same Availability Zone as your EC2 instance. An EBS volume can only be attached to an EC2 instance within the same Availability Zone. You can mount and unmount EBS volumes to any EC2 instance within the same zone as needed.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-18 a', 'CP-2 a 1']
  tag nist_r4:               ['AC-18 a', 'CP-2 a 1']
  tag cci:                   ['CCI-002323', 'CCI-000443']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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

  describe 'EBS volumes with encryption disabled' do
    subject { aws_ebs_volumes_multi_region(regions: input('scan_regions')).where(encrypted: false).volume_ids }
    it { should be_empty }
  end
end