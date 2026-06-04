# encoding: UTF-8

control 'C-6.13' do
  title 'Ensure working of EDR'
  desc  "
    TODO: description missing in source XCCDF
  "
  desc  'rationale', "
    TODO: description missing in source XCCDF
  "
  desc  'check', "
    1. Preparing the Environment for EDR - Before getting started with EDR, you must prepare the environment that you want to back up.
    2. Preparing the Source Server - Allow direct access to Elastic Disaster Recovery and Amazon S3 AWS service API endpoints through HTTPS protocol (TCP port 443). Direct outbound TCP port 1500 from the source server to the staging area subnet, which contains the replication servers. 
    3. Preparing the Staging Area Subnet - Allow Direct access to EDR, S3, and EC2 through HTTPS protocol (TCP port 443)
    Direct inbound TCP port 1500 for replication traffic
    4. Accessing the AWS Elastic Disaster Recovery Console - 
    	- Search for \"AWS Elastic Disaster Recovery\" in the AWS Console.
    	- Select \"Elastic Disaster Recovery\"
    5. Configuring the Replication Settings Template - Select 
    ```Configure and Initialize```in in the AWS Elastic Disaster Recovery screen. You will be navigated to setup your replication settings template. This will create a staging area in a subnet of your choice and a replication server instance types. The default replication server instance type will be a t3 micro EC2 instance. This is good for normal workloads with small I/O operations.
    6. Next, configure EBS encryption and volume types. This will depend on your workload requirements. 
    7. To encrypt EBS volumes, leave the setting as \"default.\" If you wish to make a custom encryption setting, you will need to create an AWS KMS key.  
    8. Configure the security group to your specific needs. Remember what ports need to be opened on inbound / outbound traffic that was specified in previous steps:
    You can choose how you want your data routed and if you want to throttle network traffic to reserve bandwidth. To keep your data as secure as possible, it's recommended to get set up with a VPN or AWS direct connect, so your backups are not traveling over the public internet. 
    Point in time policy defines the snapshot retention time. Because Elastic Disaster Recovery service uses incremental backups, it's not necessary to keep old copies of backups. 
    Now, you're ready to launch this template.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.13'
  tag cis_rid:               '6.13'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0613r1_rule'
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
  # to evidence-class attestation (sparc-validate#154/#8): resolves the per-control
  # override else attestation_uri(:boundary, 'C-6.13'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_13_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.13') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure working of EDR (attestation-required)' do
      skip "attestation-required: 'Ensure working of EDR' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_13_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.13 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end