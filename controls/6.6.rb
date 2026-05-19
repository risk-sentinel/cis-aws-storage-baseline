# encoding: UTF-8

control 'C-6.6' do
  title 'Ensure installation of the AWS Replication Agent'
  desc  "
    Set up and verify the installation of the AWS Replication Agent on all relevant systems to facilitate efficient and reliable data replication. This process includes downloading the agent, configuring it according to best practices, and ensuring it is correctly integrated with your AWS environment. Regularly check the agent's performance and update it as needed to maintain optimal functionality and data integrity during replication processes.

    Installing the AWS Replication Agent is crucial for enabling efficient and reliable data replication, ensuring that critical data is accurately duplicated across systems. Proper configuration and integration with your AWS environment optimize the agent's performance, enhancing data availability and disaster recovery capabilities. Regular checks and updates of the replication agent help maintain its effectiveness, ensuring data integrity and minimizing the risk of replication failures.
  "
  desc  'rationale', "
    Set up and verify the installation of the AWS Replication Agent on all relevant systems to facilitate efficient and reliable data replication. This process includes downloading the agent, configuring it according to best practices, and ensuring it is correctly integrated with your AWS environment. Regularly check the agent's performance and update it as needed to maintain optimal functionality and data integrity during replication processes.

    Installing the AWS Replication Agent is crucial for enabling efficient and reliable data replication, ensuring that critical data is accurately duplicated across systems. Proper configuration and integration with your AWS environment optimize the agent's performance, enhancing data availability and disaster recovery capabilities. Regular checks and updates of the replication agent help maintain its effectiveness, ensuring data integrity and minimizing the risk of replication failures.
  "
  desc  'check', "
    1. On the source servers page, from Actions, choose add servers to obtain the agent installer link.
    2. On your source server (in our case, the EC2 instance that was already created) download the appropriate agent installer for your operating system.
    	- For Linux instance on US-East-1. Substitute your region in the {Region} brackets of this command: 
    ```
    wget -O ./aws-replication-installer-init https://aws-elastic-disaster-recovery-us-east-1.s3.us-east-1.amazonaws.com/latest/linux/aws-replication-installer-init
    ```
    3. Run following command:
    ```
    chmod +x aws-replication-installer-init; sudo ./aws-replication-installer-init
    ```
    4. Type in your region. Region is case sensitive: if you're in us-east-1, make sure you type \"us-east-1\".
    5. If you're using SSH, you will be prompted with your activation ID and secret activation key. Make sure you have those accessible for the IAM user you're using. You can generate a new key from the IAM dashboard if you forgot to save your key. 
    6. Select \"Enter\" to replicate all servers.
    7. All servers should replicate.
    8. Make sure your OS is up to date. If you run into an error replicating your devices, view the documentation on troubleshooting the AWS replication installation here: https://docs.aws.amazon.com/mgn/latest/ug/installation-requirements.html.
    9. If install runs successfully, the source server will appear in your Elastic Disaster Recovery Console dashboard on the \"source servers\" page. This will signify the beginning of the replication process.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'AC-2 c', 'AC-2 (2)']
  tag cci:                   ['CCI-001678', 'CCI-002113', 'CCI-001682']
  tag cis_number:            '6.6'
  tag cis_rid:               '6.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0606r1_rule'
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

  describe 'Ensure installation of the AWS Replication Agent' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0606r1_rule.'
  end
end
