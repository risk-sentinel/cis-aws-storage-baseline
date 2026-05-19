# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure EC2 Kernel compatibility with Lustre'
  desc  "
    The latest kernel included with the Ubuntu Amazon EC2 AMI is not compatible with the Lustre service, which is crucial for mounting the cache on your EC2 instance. To downgrade your kernel, specific prerequisites must be met if you are using the default Ubuntu machine image as of November 8, 2023.

    The latest kernel version is not supported by Lustre, and meeting the prerequisites for downgrading will allow you to leverage Lustre's high-performance file system capabilities effectively. This ensures optimal data access and processing efficiency on your EC2 instance.
  "
  desc  'rationale', "
    The latest kernel included with the Ubuntu Amazon EC2 AMI is not compatible with the Lustre service, which is crucial for mounting the cache on your EC2 instance. To downgrade your kernel, specific prerequisites must be met if you are using the default Ubuntu machine image as of November 8, 2023.

    The latest kernel version is not supported by Lustre, and meeting the prerequisites for downgrading will allow you to leverage Lustre's high-performance file system capabilities effectively. This ensures optimal data access and processing efficiency on your EC2 instance.
  "
  desc  'check', "
    Follow the steps to downgrade your kernel:
    1. List all of the available Lustre packages by typing in this command: sudo apt-cache search lustre-client-modules. This will show a list of supported modules with corresponding kernel versions in ascending order from top to bottom. The most recent version in this case is \"lustre-client-modules-5.15.0-1049-aws. Save this information for the next commands.
    2. Install the most recent linux image that supports the Lustre client with this command: 
    ```
    sudo apt-get install -y linux-image-5.15.0-1049-aws
    sudo sed -i 's/GRUB_DEFAULT=.\\+/GRUB\\_DEFAULT=\"Advanced options for Ubuntu>Ubuntu, with Linux 5.15.0-1049-aws\"/' /etc/default/grub
    ```
    3. Reboot your system by typing \"sudo reboot\".
    4. Install the correct Lustre module: .
    ```
    sudo apt-get install -y lustre-client-modules-$(uname -r)
    ```
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['IA-5 (1) (e)', 'AC-2 c', 'SI-4 (5)', 'SI-4 a 1']
  tag cci:                   ['CCI-000200', 'CCI-002113', 'CCI-002663', 'CCI-001253']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0406r1_rule'
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

  describe 'Ensure EC2 Kernel compatibility with Lustre' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0406r1_rule.'
  end
end
