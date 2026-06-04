# encoding: UTF-8

control 'C-4.2' do
  title 'Amazon Elastic File Cache'
  desc  "
    Amazon File Cache is available in the following AWS Regions:
    1. US East (N. Virginia)
    2. US East (Ohio)
    3. US West (Oregon)
    4. Canada (Central)
    5. Europe (Frankfurt)
    6. Europe (Ireland)
    7. Europe (London)
    8. Europe (Stockholm)
    9. Asia Pacific (Hong Kong)
    10. Asia Pacific (Mumbai)
    11. Asia Pacific (Seoul)
    12. Asia Pacific (Tokyo)
    13. Asia Pacific (Singapore)
    14. Asia Pacific (Sydney)

    Amazon Elastic File Cache Compatibility:
    In order to use AWS FSx, you must ensure that the operating system you're using on the compute instance is compatible with AWS FSx. Below are the compatible operating systems:
    1. Amazon Linux 2 and Amazon Linux
    2. Red Hat Enterprise Linux (RHEL)
    3. CentOS
    4. Rocky Linux
    5. Ubuntu. 
    The Lustre client must be installed on these systems in order for the FSx service to work.

    The rationale behind creating Amazon Elastic File Cache is to enhance the performance and scalability of cloud-based applications by providing a high-speed, scalable file caching solution. This service reduces latency and improves access times for frequently accessed data, thereby optimizing application performance and user experience. Additionally, it helps manage and reduce storage costs by efficiently utilizing cached data, ensuring that resources are used effectively while maintaining high performance standards.
  "
  desc  'rationale', "
    Amazon File Cache is available in the following AWS Regions:
    1. US East (N. Virginia)
    2. US East (Ohio)
    3. US West (Oregon)
    4. Canada (Central)
    5. Europe (Frankfurt)
    6. Europe (Ireland)
    7. Europe (London)
    8. Europe (Stockholm)
    9. Asia Pacific (Hong Kong)
    10. Asia Pacific (Mumbai)
    11. Asia Pacific (Seoul)
    12. Asia Pacific (Tokyo)
    13. Asia Pacific (Singapore)
    14. Asia Pacific (Sydney)

    Amazon Elastic File Cache Compatibility:
    In order to use AWS FSx, you must ensure that the operating system you're using on the compute instance is compatible with AWS FSx. Below are the compatible operating systems:
    1. Amazon Linux 2 and Amazon Linux
    2. Red Hat Enterprise Linux (RHEL)
    3. CentOS
    4. Rocky Linux
    5. Ubuntu. 
    The Lustre client must be installed on these systems in order for the FSx service to work.

    The rationale behind creating Amazon Elastic File Cache is to enhance the performance and scalability of cloud-based applications by providing a high-speed, scalable file caching solution. This service reduces latency and improves access times for frequently accessed data, thereby optimizing application performance and user experience. Additionally, it helps manage and reduce storage costs by efficiently utilizing cached data, ensuring that resources are used effectively while maintaining high performance standards.
  "
  desc  'check', "
    Creating Amazon Elastic File Cache:
    Before you can start using Amazon Elastic File Cache, you must set up an Amazon Elastic Compute Instance and an S3 bucket. 
    We're going to create a new EC2 instance and S3 bucket for the sake of this tutorial. 

    Creating an EC2 instance for FSx:
    Make sure that whatever AMI you select is compatible with Lustre 2.12 client. 
    	- Navigate to the Amazon EC2 console.
    	- Select \"Launch Instance\".
    	- Give your server a name. 
    	- Select \"Ubuntu\" or an operating system that's compatible with FSx.		
    	- Select default VPC and security group.
    	- Select or create private SSH keys.
    	- Leave the rest of the settings default.
    	- Create Instance.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 (2)', 'AU-4', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-001682', 'CCI-001848', 'CCI-000051']
  tag cis_number:            '4.2'
  tag cis_rid:               '4.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0402r1_rule'
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
  # to evidence-class attestation (sparc-validate#154/#8): resolves the per-control
  # override else attestation_uri(:boundary, 'C-4.2'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_4_2_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.2') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Amazon Elastic File Cache (attestation-required)' do
      skip "attestation-required: 'Amazon Elastic File Cache' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_2_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.2 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end