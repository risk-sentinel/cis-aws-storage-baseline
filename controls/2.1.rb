# encoding: UTF-8

control 'C-2.1' do
  title 'Ensure creating EC2 instance with EBS'
  desc  "
    EBS are storage volumes that you attach to Amazon EC2 instances. 
    After you attach a volume to an instance, you can use it in the same way you would use a local hard
    drive attached to a computer, for example to store files or to install applications.
  "
  desc  'rationale', "
    EBS are storage volumes that you attach to Amazon EC2 instances. 
    After you attach a volume to an instance, you can use it in the same way you would use a local hard
    drive attached to a computer, for example to store files or to install applications.
  "
  desc  'check', "
    Creating EC2 instance with Volume:-
    To create an EC2 instance with a volume in AWS, you can follow these general steps:
    1. Initializing a Secure EC2 Instance:
    Navigate to the EC2 dashboard within your AWS console. Make sure you're in the region that's right for you. 
    Select \"Launch Instance\".
    2. Naming the EC2 instance:
    Name your EC2 instance according to the proper naming convention set by your organization.
    3. Configure the operating system:
    You can choose any operating system according to your needs. In this tutorial, Ubuntu is the OS of choice.
    4. Create a key pair
    Next, create a key pair. You will need this to login your EC2 instance. We're going to log in via SSH.
    Select \"Create new key pair\". Give your key a name, select RSA encryption, and select Open SSH. 
    As you can see by the prompt, you will need to keep the private key that's generated secure on your local computer. This is how you will access your EC2 instance. Select \"Create key pair\" your secret key will start downloading as a \".pem\" file. 

    Add Storage:
    1. Click \"Add New Volume\" to add a new volume.
    2. Specify the volume type (e.g., General Purpose SSD, Provisioned IOPS SSD, Magnetic).
    3. Set the size of the volume in GB minimum of 8GB.
    4. You can add multiple volumes if needed.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.1'
  tag cis_rid:               '2.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0201r1_rule'
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

  describe 'Ensure creating EC2 instance with EBS' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0201r1_rule.'
  end
end
