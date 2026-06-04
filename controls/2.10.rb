# encoding: UTF-8

control 'C-2.10' do
  title 'Ensure Resource Access via Tag-based Policies'
  desc  "
    For optimal granularity in EC2 access, configuring IAM policies via tags proves highly effective. This involves editing the JSON text editor to specify access permissions based on specific tags. In the provided example, I'm granting the \"developers\" group access exclusively to the newly created EC2 image, as illustrated in the attached screenshot depicting the policy creation process.

    Implementing IAM policies based on tags in EC2 enables administrators to finely tailor access control, granting permissions dynamically according to resource attributes. This approach enhances security and scalability by aligning access rights with specific resource requirements while minimizing manual intervention.
  "
  desc  'rationale', "
    For optimal granularity in EC2 access, configuring IAM policies via tags proves highly effective. This involves editing the JSON text editor to specify access permissions based on specific tags. In the provided example, I'm granting the \"developers\" group access exclusively to the newly created EC2 image, as illustrated in the attached screenshot depicting the policy creation process.

    Implementing IAM policies based on tags in EC2 enables administrators to finely tailor access control, granting permissions dynamically according to resource attributes. This approach enhances security and scalability by aligning access rights with specific resource requirements while minimizing manual intervention.
  "
  desc  'check', "
    1. Review IAM Policies:
       - Access the IAM console in the AWS Management Console.
       - Navigate to the \"Policies\" section and review policies associated with EC2 resources.
       - Ensure that policies utilize condition keys related to EC2 tags for granting access.

    2. IAM Policy Simulator:
       - Utilize the IAM Policy Simulator to simulate access scenarios based on EC2 tags.
       - Test various tag-based policy configurations to verify that access is granted or denied appropriately.

    3. CloudTrail Analysis:
       - Access the CloudTrail console and review logs related to IAM policy changes.
       - Look for API calls related to modifications of policies using tag-based conditions.

    4. AWS Config Rules:
       - Configure AWS Config rules to monitor IAM policies for tag-based conditions.
       - Set up rules to detect policies that do not include tag-based conditions or are overly permissive.

    5. Manual Review:
       - Manually inspect IAM policies to ensure they include tag-based conditions where applicable.
       - Verify that policies accurately reflect the intended access control based on EC2 resource tags.

    6. Automated Scanning:
       - Utilize third-party AWS security tools that offer automated scanning and analysis of IAM policies for tag-based conditions.
       - Configure these tools to regularly scan IAM policies and identify any deviations from best practices.

    7. Continuous Monitoring:
       - Implement continuous monitoring solutions to track changes to IAM policies in real-time.
       - Set up alerts to notify administrators of any unauthorized modifications or policy changes that do not adhere to tag-based access control principles.
  "
  desc  'fix', "
    1. Policy Adjustment:
       - Review existing IAM policies associated with EC2 resources to ensure they include tag-based conditions where applicable.
       - Modify policies to incorporate tag-based conditions for granular access control, ensuring that access is granted or denied based on resource attributes.

    2. IAM Policy Simulator Validation:
       - Utilize the IAM Policy Simulator to validate the effectiveness of policy adjustments.
       - Test various access scenarios to verify that policies accurately reflect the intended access control based on EC2 resource tags.

    3. AWS Config Remediation:
       - Configure AWS Config rules to automatically remediate IAM policies that do not include tag-based conditions.
       - Set up remediation actions to adjust policies to adhere to tag-based access control principles automatically.

    4. Employee Training:
       - Provide training to IAM administrators on best practices for crafting IAM policies based on tags.
       - Ensure that administrators understand the importance of utilizing tag-based conditions for granular access control in EC2.

    5. Monitoring and Alerting:
       - Implement continuous monitoring solutions to detect and alert on any deviations from tag-based access control policies.
       - Set up alerts to notify administrators of any unauthorized modifications or policy changes that do not adhere to tag-based access control principles.

    6. Documentation and Documentation:
       - Document changes made to IAM policies to include tag-based conditions.
       - Maintain up-to-date documentation on IAM policies and access controls for reference during audits and compliance assessments.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AC-8 a']
  tag cci:                   ['CCI-001682', 'CCI-000051']
  tag cis_number:            '2.10'
  tag cis_rid:               '2.10'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0210r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.10'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_10_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.10') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure Resource Access via Tag-based Policies (attestation-required)' do
      skip "attestation-required: 'Ensure Resource Access via Tag-based Policies' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_10_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.10 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end