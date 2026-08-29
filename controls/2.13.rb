# encoding: UTF-8

control 'C-2.13' do
  title 'Ensure creating an SNS subscription'
  desc  "
    Create an SNS notification to send to the system administrator's email address.
  "
  desc  'rationale', "
    Create an SNS notification to send to the system administrator's email address.
  "
  desc  'check', "
    Creating an SNS subscription:
    1. Navigate to SNS service in the AWS console - https://us-east-2.console.aws.amazon.com/sns/v3/home?region=us-east-2#/homepage (make sure you are in the correct region).
    2. Navigate to \"topics\".
    3. Create a new topic.
    4. Select the ARN of the topic.
    5. Select the \"Email\" protocol if you wish to have the alarms delivered to your email.
    6. Enter the correct email address of an administrator.
    7. Select \"Create Subscription\".

    To attach the SNS notification service to the alarm - select the SNS subscription that you just created and create the alarm.
  "
  desc  'fix', "
    Deliver storage alarms to a subscribed topic so they reach a person.

    1. Create the topic and subscribe the operations distribution list. Use a shared
       mailbox rather than an individual, so the alert survives staff changes:

        ```
        aws sns create-topic --name storage-alarms
        aws sns subscribe --topic-arn <topic-arn> --protocol email --notification-endpoint <ops-distribution-list>
        ```

    2. Confirm the subscription from the email AWS sends. An unconfirmed
       subscription accepts the alarm and silently delivers nothing.
    3. Enable server-side encryption on the topic with a KMS key, and apply a topic
       policy restricting `sns:Publish` to CloudWatch in your account.
    4. Point the storage alarms at the topic and verify end to end by setting an
       alarm temporarily into ALARM state.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.13'
  tag cis_rid:               '2.13'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0213r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.13'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_2_13_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.13') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure creating an SNS subscription (attestation-required)' do
      skip "attestation-required: 'Ensure creating an SNS subscription' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_13_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.13 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end