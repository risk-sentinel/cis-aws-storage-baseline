# encoding: UTF-8

control 'C-3.8' do
  title 'Ensure managing mount target security groups'
  desc  "
    Managing security groups for mount targets is essential for controlling access to your Amazon EFS file systems. By configuring these security groups, you ensure that only authorized network traffic can access your file systems, enhancing security. Regular reviews and updates of security group rules maintain strict access control, protecting your data from unauthorized access and potential breaches.

    The rationale for managing security groups for mount targets is to ensure robust access control and security for your Amazon EFS file systems. By configuring these security groups, you restrict access to only authorized network traffic, thereby minimizing the risk of unauthorized access and potential data breaches. Regularly reviewing and updating these rules helps maintain strong security measures and compliance with organizational policies and industry standards.
  "
  desc  'rationale', "
    Managing security groups for mount targets is essential for controlling access to your Amazon EFS file systems. By configuring these security groups, you ensure that only authorized network traffic can access your file systems, enhancing security. Regular reviews and updates of security group rules maintain strict access control, protecting your data from unauthorized access and potential breaches.

    The rationale for managing security groups for mount targets is to ensure robust access control and security for your Amazon EFS file systems. By configuring these security groups, you restrict access to only authorized network traffic, thereby minimizing the risk of unauthorized access and potential data breaches. Regularly reviewing and updating these rules helps maintain strong security measures and compliance with organizational policies and industry standards.
  "
  desc  'check', "
    1. Navigate to EFS.
    2. Select file systems.
    3. Click the radio box and select \"view details\".
    4. Select the \"manage\" button.
    5. Select \"Networking\" tab.
    6. This will bring up a screen for each of your mount points.
    7. To edit Security Groups, select \"Manage\".From here, you can edit security groups for each mount point. This gives you control of how traffic can flow between each subnet.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-17 (1)', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000067', 'CCI-000051']
  tag cis_number:            '3.8'
  tag cis_rid:               '3.8'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0308r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.8'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_3_8_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.8') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure managing mount target security groups (attestation-required)' do
      skip "attestation-required: 'Ensure managing mount target security groups' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_8_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.8 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end