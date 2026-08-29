# encoding: UTF-8

control 'C-6.12' do
  title 'Ensure CloudWatch Metrics for AWS EDR'
  desc  "
    Set up and monitor AWS CloudWatch metrics for Endpoint Detection and Response (EDR) to track and analyze the performance and security of your AWS environment. This involves configuring CloudWatch to collect detailed logs and metrics on EDR activities, such as threat detections, response actions, and system health. Regularly review these metrics to identify trends, anomalies, and potential security issues, enabling proactive management and timely responses to ensure the effectiveness of your EDR solution.

    Implementing AWS CloudWatch metrics for Endpoint Detection and Response (EDR) is essential for maintaining a secure and efficient AWS environment. By collecting detailed logs and metrics on EDR activities, you gain valuable insights into the performance and health of your security measures. Regular review of these metrics allows for the early detection of trends, anomalies, and potential security threats, enabling proactive management and swift responses to maintain the integrity and effectiveness of your EDR solution. This continuous monitoring ensures that your security posture remains robust and adaptive to evolving threats.
  "
  desc  'rationale', "
    Set up and monitor AWS CloudWatch metrics for Endpoint Detection and Response (EDR) to track and analyze the performance and security of your AWS environment. This involves configuring CloudWatch to collect detailed logs and metrics on EDR activities, such as threat detections, response actions, and system health. Regularly review these metrics to identify trends, anomalies, and potential security issues, enabling proactive management and timely responses to ensure the effectiveness of your EDR solution.

    Implementing AWS CloudWatch metrics for Endpoint Detection and Response (EDR) is essential for maintaining a secure and efficient AWS environment. By collecting detailed logs and metrics on EDR activities, you gain valuable insights into the performance and health of your security measures. Regular review of these metrics allows for the early detection of trends, anomalies, and potential security threats, enabling proactive management and swift responses to maintain the integrity and effectiveness of your EDR solution. This continuous monitoring ensures that your security posture remains robust and adaptive to evolving threats.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console:
       - Open the [AWS Management Console](https://aws.amazon.com/console/) and sign in with your credentials.

    2. Navigate to CloudWatch:
       - In the AWS Management Console, navigate to the CloudWatch service.

    3. Create a CloudWatch Log Group:
       - Select Logs from the navigation pane.
       - Click on Create log group.
       - Enter a name for the log group and click Create.

    4. Configure AWS EDR to Send Logs to CloudWatch:
       - Go to the AWS EDR (Elastic Disaster Recovery) console.
       - In the AWS EDR console, configure your settings to send logs and metrics to the CloudWatch log group you created.

    5. Set Up CloudWatch Alarms:
       - In the CloudWatch console, select Alarms from the navigation pane.
       - Click on Create Alarm.
       - Select the metric you want to monitor from the list of AWS EDR metrics.
       - Configure the conditions for the alarm (e.g., threshold, period, etc.).
       - Set the actions to take when the alarm state is triggered (e.g., send a notification).
       - Review and create the alarm.

    6. Create CloudWatch Dashboards:
       - In the CloudWatch console, select Dashboards from the navigation pane.
       - Click on Create dashboard.
       - Enter a name for your dashboard and click Create.
       - Add widgets to the dashboard by selecting the relevant AWS EDR metrics.
       - Customize the widgets to display the data in a meaningful way (e.g., graphs, numbers).

    7. Enable CloudWatch Logs Insights:
       - In the CloudWatch console, select Logs Insights from the navigation pane.
       - Choose the log group you created for AWS EDR.
       - Use CloudWatch Logs Insights queries to analyze the log data and extract meaningful insights.

    8. Set Up CloudWatch Events:
       - In the CloudWatch console, select Events from the navigation pane.
       - Click on Create rule.
       - Define the event source and the specific events you want to capture (e.g., changes in EDR status).
       - Set the target for the event (e.g., send a notification, invoke a Lambda function).
       - Configure the rule and click Create rule.
  "
  desc  'fix', "
    Replication health is only useful if a person is told when it degrades.

    1. Create a CloudWatch log group for Elastic Disaster Recovery and configure the
       service to deliver to it.
    2. Alarm on lag and on replication state, not just on job failure. The failure
       that matters is a server that has quietly stopped replicating while still
       appearing in the console.
    3. Send alarms to an SNS topic with a confirmed subscription, so the notification
       reaches a monitored mailbox rather than an unconfirmed endpoint.
    4. Confirm the alarm path end to end by driving an alarm into ALARM state, rather
       than assuming delivery works.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.12'
  tag cis_rid:               '6.12'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0612r1_rule'
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
  # override else attestation_uri(:boundary, 'C-6.12'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_6_12_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.12') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure CloudWatch Metrics for AWS EDR (attestation-required)' do
      skip "attestation-required: 'Ensure CloudWatch Metrics for AWS EDR' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_12_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.12 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end