# encoding: UTF-8

control 'C-6.4' do
  title 'Ensure configuration of replication settings'
  desc  "
    Set up and maintain the replication settings to ensure accurate and efficient data duplication across systems. Proper configuration includes specifying source and target locations, defining replication schedules, and setting bandwidth limits to optimize performance. Regularly review and update these settings to accommodate changes in data volume and network conditions, ensuring data integrity and availability during replication processes.

    Proper configuration of replication settings is essential to ensure data consistency and availability across systems. Accurate replication schedules and bandwidth management optimize performance and prevent network congestion. Regular reviews and updates of these settings help adapt to changes in data volume and network conditions, maintaining efficient and reliable data replication processes.
  "
  desc  'rationale', "
    Set up and maintain the replication settings to ensure accurate and efficient data duplication across systems. Proper configuration includes specifying source and target locations, defining replication schedules, and setting bandwidth limits to optimize performance. Regularly review and update these settings to accommodate changes in data volume and network conditions, ensuring data integrity and availability during replication processes.

    Proper configuration of replication settings is essential to ensure data consistency and availability across systems. Accurate replication schedules and bandwidth management optimize performance and prevent network congestion. Regular reviews and updates of these settings help adapt to changes in data volume and network conditions, maintaining efficient and reliable data replication processes.
  "
  desc  'check', "
    1. Select \"Configure and Initialize\" in in the AWS Elastic Disaster Recovery screen. You will be navigated to setup your replication settings template.  This will create a staging area in a subnet of your choice and a replication server instance types. The default replication server instance type will be a t3 micro EC2 instance. This is good for normal workloads with small I/O operations.
    2. Next, configure EBS encryption and volume types. This will depend on your workload requirements. To encrypt EBS volumes, leave the setting as \"default.\" If you wish to make a custom encryption setting, you will need to create an AWS KMS key. 
    3. Configure the security group to your specific needs. Remember what ports need to be opened on inbound / outbound traffic that was specified in previous steps: 
    	- Configure Additional Replication settings.
    	- You can choose how you want your data routed and if you want to throttle network traffic to reserve bandwidth. 
    To keep your data as secure as possible, it's recommended to get set up with a VPN or AWS direct connect, so your backups are not traveling over the public internet. 
    	- Point in time policy defines the snapshot retention time. Because Elastic Disaster Recovery service uses incremental backups, it's not necessary to keep old copies of backups. 
    Now, you're ready to launch this template.
  "
  desc  'fix', "
    1. Set the staging area subnet to a private subnet dedicated to replication.
    2. Enable EBS encryption for the replication volumes and choose a
       customer-managed KMS key, so replicated production data is not sitting under
       the AWS-managed default key.
    3. Size the replication server instance type to the source servers' write
       throughput. The `t3.micro` default is adequate only for low I/O workloads and
       will silently fall behind on anything busier, leaving a stale recovery point.
    4. Enable the option to use a dedicated replication server per source only where
       isolation between workloads is required, since it multiplies cost.
    5. Set a snapshot retention window that matches the recovery point objective you
       have committed to.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.4'
  tag cis_rid:               '6.4'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0604r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

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
  # override else attestation_uri(:boundary, 'C-6.4'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_6_4_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.4') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure configuration of replication settings (attestation-required)' do
      skip "attestation-required: 'Ensure configuration of replication settings' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_4_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.4 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end