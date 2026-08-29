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
    Treat the Lustre client as managed software on the instance.

    1. Install the client package matching the running kernel from the distribution
       repository, and record it in the instance's package baseline so image rebuilds
       reproduce it.
    2. Bring the client into the patch process that covers the rest of the host, so a
       client vulnerability is picked up by the same scanning that covers the OS.
    3. Reach the instance for this work through Systems Manager Session Manager
       rather than opening SSH to perform the install.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
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
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  # Procedural/operational control — the CIS Storage benchmark check-content is a
  # console setup/operational procedure, not an AWS-API-assertable state. Converted
  # to evidence-class attestation: resolves the per-control
  # override else attestation_uri(:boundary, 'C-4.5'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_4_5_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.5') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure installation and configuration of Lustre Client (attestation-required)' do
      skip "attestation-required: 'Ensure installation and configuration of Lustre Client' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_5_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.5 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end