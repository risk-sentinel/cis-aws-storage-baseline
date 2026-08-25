# encoding: UTF-8

control 'C-6.2' do
  title 'Ensure AWS Disaster Recovery Configuration'
  desc  "
    It's important to understand how the network on EDR works. This isn't a simple service to configure, but it works with multiple work loads over the network. You can connect your on-premises or third-party cloud service to AWS EDR over the network. Below are the descriptions of the AWS network architecture:
    1. Your local network inside the data center or cloud
    	a.Connect an AWS Replication Agent to each of your resources.
    2. AWS Cloud Architecture
    	a. Choose the AWS Region that you want to house your disaster recovery instances.
    	b.Create AWS API Endpoints for EC2, Disaster Recovery, and S3.
    	c.Upon creation of Disaster Recovery endpoints, two subnets will be created in your VPC
    		i.Staging Area Subnets: Replication servers with EBS volumes attached to each disk on the replication servers.
    		ii.Recovery Subnets: Recovery EC2 instances attached to EBS volumes/
    	d.Connect local network over TCP port 443 to EDR and S3
    	e.Connect local replication agent to AWS replication servers over TCP port 1500
    	f.Connectivity out of staging area: Connect staging area on AWS to EDR over TCP port 443
    	g.Allow connection to S3 over TCP 443
    	h.Allow connectivity to EC2 over TCP 443 to connect to API Endpoint
  "
  desc  'rationale', "
    It's important to understand how the network on EDR works. This isn't a simple service to configure, but it works with multiple work loads over the network. You can connect your on-premises or third-party cloud service to AWS EDR over the network. Below are the descriptions of the AWS network architecture:
    1. Your local network inside the data center or cloud
    	a.Connect an AWS Replication Agent to each of your resources.
    2. AWS Cloud Architecture
    	a. Choose the AWS Region that you want to house your disaster recovery instances.
    	b.Create AWS API Endpoints for EC2, Disaster Recovery, and S3.
    	c.Upon creation of Disaster Recovery endpoints, two subnets will be created in your VPC
    		i.Staging Area Subnets: Replication servers with EBS volumes attached to each disk on the replication servers.
    		ii.Recovery Subnets: Recovery EC2 instances attached to EBS volumes/
    	d.Connect local network over TCP port 443 to EDR and S3
    	e.Connect local replication agent to AWS replication servers over TCP port 1500
    	f.Connectivity out of staging area: Connect staging area on AWS to EDR over TCP port 443
    	g.Allow connection to S3 over TCP 443
    	h.Allow connectivity to EC2 over TCP 443 to connect to API Endpoint
  "
  desc  'check', "
    TODO: check content missing in source XCCDF
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.2'
  tag cis_rid:               '6.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0602r1_rule'
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
  # override else attestation_uri(:boundary, 'C-6.2'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_2_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.2') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure AWS Disaster Recovery Configuration (attestation-required)' do
      skip "attestation-required: 'Ensure AWS Disaster Recovery Configuration' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_2_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.2 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end