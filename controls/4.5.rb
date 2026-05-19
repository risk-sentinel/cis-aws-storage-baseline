# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure installation and configuration of Lustre Client'
  desc  "
    To utilize the newly created File Cache, you must install the Lustre Client on your EC2 instance.

    The Lustre Client facilitates efficient communication between the EC2 instance and the File Cache, ensuring high-performance data access and improved overall system efficiency. This setup is crucial for optimizing data processing and leveraging the benefits of the File Cache.
  "
  desc  'rationale', "
    To utilize the newly created File Cache, you must install the Lustre Client on your EC2 instance.

    The Lustre Client facilitates efficient communication between the EC2 instance and the File Cache, ensuring high-performance data access and improved overall system efficiency. This setup is crucial for optimizing data processing and leveraging the benefits of the File Cache.
  "
  desc  'check', "
    Follow along to install the Lustre Client on Ubuntu 22.04:
    1. Launch your EC2 instance. Navigate to the folder of your secure key and ssh into the instance using this command:
    		- ssh -i \"{KEY.pem}\" ubuntu@{your ec2 instance} 
    		- When prompted to log in with the SSH key, enter in \"yes\"
    		- You should now be connected to your EC2 instance. 
    2. Run the following command to download and install the public Lustre key:  
    ```
    wget -O - https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-ubuntu-public-key.asc | gpg --dearmor | sudo tee /usr/share/keyrings/fsx-ubuntu-public-key.gpg >/dev/null
    ```
    3. Add the AWS Lustre package repository to your local package manager using the following command:
    ```
    sudo bash -c 'echo \"deb [signed-by=/usr/share/keyrings/fsx-ubuntu-public-key.gpg] https://fsx-lustre-client-repo.s3.amazonaws.com/ubuntu jammy main\" > /etc/apt/sources.list.d/fsxlustreclientrepo.list && apt-get update'
    ```
    4. Determine which kernel is currently running on your client instance and update as needed. The AWS Lustre client on Ubuntu 22.02 requires kernel 5.15.0.1020-aws or later for both x86 based EC2 instances and Arm-based EC2 instanced powered by AWS Graviton processors:
    a.	Run the following command to find out which kernel your machine is running:
    uname -r
    	- If your kernel is not up to date, run the following command: This will install the kernel update, Lustre client update, as well as reboot your system. 
    ```
    sudo apt install -y linux-aws lustre-client-modules-aws && sudo reboot
    ```
    	- If your kernel is up to date and you just want to install the latest Lustre version, run this command:
    ```
    sudo apt install -y lustre-client-modules-$(uname -r)
    ```
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'IA-5 (1) (e)', 'SI-4 (5)', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000200', 'CCI-002663', 'CCI-000051']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0405r1_rule'
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

  describe 'Ensure installation and configuration of Lustre Client' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0405r1_rule.'
  end
end
