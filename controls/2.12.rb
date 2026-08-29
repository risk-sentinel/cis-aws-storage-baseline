# encoding: UTF-8

control 'C-2.12' do
  title 'Ensure Monitoring EC2 and EBS with CloudWatch'
  desc  "
    CloudWatch is an AWS monitoring service that allows you to keep an eye on your AWS resources. You can track metrics via log files or worldclass data visuals. AWS CloudWatch allows the administrator to keep an eye on his/her AWS resources. You can set up alarms, monitor activity, and analyze log data. CloudWatch is a must to keep your AWS EBS and EC2 resources secure.

    Using CloudWatch to monitor EC2 instances and EBS volumes is essential for enhancing operational oversight and ensuring optimal performance within the AWS environment. This approach provides real-time insights into resource usage and system health, enabling proactive adjustments and timely responses to potential issues, thereby maintaining high availability and efficiency.
  "
  desc  'rationale', "
    CloudWatch is an AWS monitoring service that allows you to keep an eye on your AWS resources. You can track metrics via log files or worldclass data visuals. AWS CloudWatch allows the administrator to keep an eye on his/her AWS resources. You can set up alarms, monitor activity, and analyze log data. CloudWatch is a must to keep your AWS EBS and EC2 resources secure.

    Using CloudWatch to monitor EC2 instances and EBS volumes is essential for enhancing operational oversight and ensuring optimal performance within the AWS environment. This approach provides real-time insights into resource usage and system health, enabling proactive adjustments and timely responses to potential issues, thereby maintaining high availability and efficiency.
  "
  desc  'check', "
    Creating an AWS CloudWatch Dashboard:
    1. Navigate to the AWS CloudWatch Console - https://us-east-2.console.aws.amazon.com/cloudwatch/home?region=us-east-2#home.
    2. Select the dashboard type that's right for you. Give the dashboard a name. Name the dashboard as something memorable. You can select which resources you want to monitor. Select \"EBS.\"
    3. Create an alarm - Alarms are important to send you an alert as soon as something suspicious happens on your volume. You can create an alarm to alert you when a certain threshold of IOPS are reached. To create alarm, follow steps -
    	- Go to \"Alarms\" on the left hand side of the CloudWatch dashboard.
    	- Select \"Create a new alarm\".
    	- Select \"EBS\".
    	- Select what you want to monitor. We're going to choose to monitor the write operations of an EBS volume.
    	- Go back to the volume that was created in EC2 dashboard and copy the volume ID under the \"volume ID\" field. 
    	- Configure the settings that you want to trigger an alarm.
    	- Move onto the next step before continuing.
  "
  desc  'fix', "
    1. Enable CloudWatch Monitoring:
       - Access the AWS Management Console, navigate to the EC2 dashboard, and select the instances and EBS volumes.
       - Enable detailed monitoring on each EC2 instance and EBS volume to collect data at a higher granularity.

    2. Configure CloudWatch Alarms:
       - In the CloudWatch console, set up alarms based on key performance metrics such as CPU utilization, disk read/write operations, and network traffic.
       - Configure these alarms to notify administrators via email or SMS when thresholds are breached, allowing for immediate action.

    3. Establish Baselines:
       - Analyze historical performance data from CloudWatch to establish baseline performance metrics for each instance and volume.
       - Use these baselines to identify abnormal behavior or performance degradation over time.

    4. Automate Responses:
       - Utilize AWS CloudWatch Events and AWS Lambda to automate responses to specific alarms, such as scaling operations or initiating recovery processes.
       - Ensure these automated scripts are tested and reflect the operational policies of your organization.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_number:            '2.12'
  tag cis_rid:               '2.12'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0212r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.12'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_12_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.12') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure Monitoring EC2 and EBS with CloudWatch (attestation-required)' do
      skip "attestation-required: 'Ensure Monitoring EC2 and EBS with CloudWatch' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_12_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.12 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end