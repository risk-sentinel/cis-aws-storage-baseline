# encoding: UTF-8

control 'C-3.3' do
  title 'Ensure EFS and VPC Integration'
  desc  "
    You can use EFS as a network file system across availability zones on a virtual private cloud. This capability allows the organization to create a highly available file sharing solution. Leveraging AWS VPC and EC2 in tandem with AWS EFS makes for a highly available and scalable cloud file storage solution.

    Redundancy and scalability are crucial for maintaining uninterrupted services. By integrating these AWS services, users can harness the full power of AWS, ensuring a resilient and scalable infrastructure.
  "
  desc  'rationale', "
    You can use EFS as a network file system across availability zones on a virtual private cloud. This capability allows the organization to create a highly available file sharing solution. Leveraging AWS VPC and EC2 in tandem with AWS EFS makes for a highly available and scalable cloud file storage solution.

    Redundancy and scalability are crucial for maintaining uninterrupted services. By integrating these AWS services, users can harness the full power of AWS, ensuring a resilient and scalable infrastructure.
  "
  desc  'check', "
    ### Audit Procedures for AWS Redundancy and Scalability

    1. Create Mount Targets in Each Availability Zone: Ensure EFS is attached in each availability zone by creating mount targets in each subnet. Although multiple subnets can exist per availability zone, verify that EFS is configured to work with one subnet per zone to maintain redundancy.

    2. Monitor EFS with CloudWatch: Use AWS CloudWatch to automatically monitor your EFS service. Check that alarms are configured and logs and events are tracked effectively, providing real-time insights into the performance and health of your file systems.
  "
  desc  'fix', "
    Create an EC2 instance in each availability zone within your VPC.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'SI-4 (5)', 'AC-8 a', 'CM-6 a']
  tag cci:                   ['CCI-001199', 'CCI-002663', 'CCI-000051', 'CCI-000363']
  tag cis_number:            '3.3'
  tag cis_rid:               '3.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0303r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.3'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_3_3_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.3') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure EFS and VPC Integration (attestation-required)' do
      skip "attestation-required: 'Ensure EFS and VPC Integration' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_3_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.3 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end