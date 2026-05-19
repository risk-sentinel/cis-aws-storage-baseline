# encoding: UTF-8

control 'C-6.11' do
  title 'Ensure execution of a failback'
  desc  "
    This method involves transitioning operations back from the backup or recovery system to the primary system after the resolution of a disruption or disaster. You can execute a failback either to the original server, ensuring continuity and restoring the previous state, or to a new server, which might be necessary if the original server is compromised or no longer functional. The failback process ensures that all updated data and configurations are transferred back, maintaining the integrity and functionality of the primary system.

    A failback is crucial for restoring normal operations after a disaster recovery scenario. Transitioning operations back to the primary system ensures continuity and leverages the original environment's configurations and settings. This process can be directed either to the original server, maintaining the existing infrastructure, or to a new server if the original is compromised. Ensuring all data and configurations are accurately transferred back preserves system integrity and functionality, reducing downtime and allowing the organization to resume normal operations efficiently.
  "
  desc  'rationale', "
    This method involves transitioning operations back from the backup or recovery system to the primary system after the resolution of a disruption or disaster. You can execute a failback either to the original server, ensuring continuity and restoring the previous state, or to a new server, which might be necessary if the original server is compromised or no longer functional. The failback process ensures that all updated data and configurations are transferred back, maintaining the integrity and functionality of the primary system.

    A failback is crucial for restoring normal operations after a disaster recovery scenario. Transitioning operations back to the primary system ensures continuity and leverages the original environment's configurations and settings. This process can be directed either to the original server, maintaining the existing infrastructure, or to a new server if the original is compromised. Ensuring all data and configurations are accurately transferred back preserves system integrity and functionality, reducing downtime and allowing the organization to resume normal operations efficiently.
  "
  desc  'check', "
    Performing the failback:
    1.	Download the failback client ISO
    2.	Attach the ISO to your original server and boot up the server.
    	- The failback client will prompt for the IAM access key and secret key generated when making the user with the permission to access the failback. It will also ask for the region of the recovery instance. Remember: regions are case sensitive. If you're in US east 1, type \"us-east-1.\"
    	- If you are failing back to the original server, the failback client will automatically detect the recovery instance and map the data volumes for replication.
    	- If you are failing back to a new server, you may need to manually specify from a list of available recovery instances and map the data volumes.
    	- The failback client will verify that the chosen recovery instance has connectivity to the Elastic Disaster Recovery service.
    	- The replication software will be downloaded to the failback client and then configured. Connectivity will be made between the failback client and the replication agent on the recovery instance to begin data replication.
    3. Return to the elastic disaster recovery console and recovery instances to see the current state of replication. Failing back to the original server will show \"rescan\" in the console, while failing back o a new instance will perform an \"initial sync.\" 
    4. After the data replication is completed, you will be able to perform the failback.
    	- Check the state of the recovery instance to ensure that it's ready to complete a failback.
    	- Select your recovery instance, then choose failback for the chosen recovery instance(s).
    	- Choose failback again the complete a failback for the chosen recovery instance(s). During the failback process, the failback client will prepare your source server for normal operation. After it has completed successfully, the failback client will return \"failback completed successfully\" in the console. 
    5. Reboot the server and return to normal operations.
    6. Clean up failback job; terminate recovery job by following the steps outlined above when we ran a drill.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.11'
  tag cis_rid:               '6.11'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0611r1_rule'
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

  describe 'Ensure execution of a failback' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0611r1_rule.'
  end
end
