# encoding: UTF-8

control 'C-6.7' do
  title 'Ensure proper configuration of the Launch Settings'
  desc  "
    Set up and verify the launch settings to ensure systems and applications start correctly and securely. This includes defining startup parameters, specifying required resources, and configuring security settings to prevent unauthorized changes. Regularly review and update these settings to align with best practices and organizational requirements, ensuring optimal performance and security at launch.

    Proper configuration of launch settings is crucial for ensuring that systems and applications start securely and perform optimally. Defining startup parameters and resource requirements prevents potential issues and enhances efficiency. Regular reviews and updates to these settings help maintain alignment with best practices and evolving organizational needs, thereby strengthening security and operational reliability from the moment of launch.
  "
  desc  'rationale', "
    Set up and verify the launch settings to ensure systems and applications start correctly and securely. This includes defining startup parameters, specifying required resources, and configuring security settings to prevent unauthorized changes. Regularly review and update these settings to align with best practices and organizational requirements, ensuring optimal performance and security at launch.

    Proper configuration of launch settings is crucial for ensuring that systems and applications start securely and perform optimally. Defining startup parameters and resource requirements prevents potential issues and enhances efficiency. Regular reviews and updates to these settings help maintain alignment with best practices and evolving organizational needs, thereby strengthening security and operational reliability from the moment of launch.
  "
  desc  'check', "
    The settings can be changed after instances have been launched, but a new instance must be launched for new launch settings to take effect. 
    1. Select launch settings on the source server page
    2. Configure launch settings
    	- On the launch settings page, next to general launch, select \"edit\"
    3. Configure EC2 launch template
    	- Enable auto assign public IP and change the instance type to a t2.medium
    4. Set version to default in the console
    5. Set the default version that was just created to default version
    6. Return to the dashboard and confirm your configurations are correct.
  "
  desc  'fix', "
    Launch settings apply to instances launched after the change, so an edit does not
    affect an already-launched recovery instance.

    1. Set the EC2 launch template used for recovery to the subnet and security
       groups that match the production posture, not the drill defaults.
    2. Turn off automatic public IP assignment. A recovery instance that comes up
       with a public address is exposed at exactly the moment attention is elsewhere.
    3. Choose an instance type matching production capacity, so a failover does not
       arrive degraded.
    4. Set the default version of the launch template, then launch a drill instance
       and confirm the settings actually took effect.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-18 a', 'IA-5 (1) (e)', 'AC-2 c', 'CM-6 a']
  tag cci:                   ['CCI-002323', 'CCI-000200', 'CCI-002113', 'CCI-000363']
  tag cis_number:            '6.7'
  tag cis_rid:               '6.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0607r1_rule'
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
  # override else attestation_uri(:boundary, 'C-6.7'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_7_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.7') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure proper configuration of the Launch Settings (attestation-required)' do
      skip "attestation-required: 'Ensure proper configuration of the Launch Settings' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_7_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.7 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end