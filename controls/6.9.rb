# encoding: UTF-8

control 'C-6.9' do
  title 'Ensure Continuous Disaster Recovery Operations'
  desc  "
    Maintain ongoing disaster recovery operations to ensure that systems and data can be swiftly restored in the event of a disruption. This involves regularly updating and testing recovery plans, monitoring replication processes, and verifying the integrity and accessibility of backups. Continuously evaluate and improve disaster recovery strategies to adapt to evolving threats and organizational changes, ensuring resilience and minimal downtime during incidents.

    Maintaining continuous disaster recovery operations is essential for ensuring that systems and data can be quickly and effectively restored following a disruption. Regular updates and tests of recovery plans, along with constant monitoring of replication processes, help verify the integrity and availability of backups. This proactive approach allows organizations to adapt to evolving threats and changes, ensuring resilience and minimizing downtime during incidents, which ultimately protects business continuity and reduces potential losses.
  "
  desc  'rationale', "
    Maintain ongoing disaster recovery operations to ensure that systems and data can be swiftly restored in the event of a disruption. This involves regularly updating and testing recovery plans, monitoring replication processes, and verifying the integrity and accessibility of backups. Continuously evaluate and improve disaster recovery strategies to adapt to evolving threats and organizational changes, ensuring resilience and minimal downtime during incidents.

    Maintaining continuous disaster recovery operations is essential for ensuring that systems and data can be quickly and effectively restored following a disruption. Regular updates and tests of recovery plans, along with constant monitoring of replication processes, help verify the integrity and availability of backups. This proactive approach allows organizations to adapt to evolving threats and changes, ensuring resilience and minimizing downtime during incidents, which ultimately protects business continuity and reduces potential losses.
  "
  desc  'check', "
    1. Review Disaster Recovery Plan:
       - Verify that a comprehensive disaster recovery (DR) plan exists and is regularly updated.
       - Ensure the DR plan includes detailed procedures for data backup, system recovery, and failover processes.
       - Check for documentation of roles and responsibilities during a disaster event.

    2. Check Backup and Replication Settings:
       - Confirm that AWS Backup is configured correctly for all critical systems and data.
       - Review the settings for Amazon RDS, EBS snapshots, S3 versioning, and other AWS services to ensure backups are automated and scheduled appropriately.
       - Ensure that replication settings are configured to replicate data across multiple AWS regions for added redundancy.

    3. Test Recovery Procedures:
       - Verify that regular recovery drills are conducted to test the DR plan's effectiveness.
       - Check the logs and reports from these drills to ensure that any issues identified are addressed promptly.
       - Ensure that the most recent recovery drill results are documented and reviewed by relevant stakeholders.

    4. Monitor and Log Review:
       - Ensure CloudWatch logs and alarms are set up to monitor backup and replication processes.
       - Review CloudTrail logs to verify that DR-related actions are being logged and monitored.
       - Check for alerts and notifications related to backup failures, replication issues, or any anomalies in the DR processes.

    5. Evaluate Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO):
       - Verify that the DR plan specifies RTO and RPO for all critical systems and data.
       - Ensure that actual recovery times and points from recent drills meet or exceed the defined objectives.

    6. Review Access Controls:
       - Check IAM policies to ensure that only authorized personnel have access to manage and initiate disaster recovery operations.
       - Verify that multi-factor authentication (MFA) is enabled for accounts with access to DR resources.

    7. Assess Security and Compliance:
       - Ensure that data encryption is enabled for all backups and replicated data.
       - Verify compliance with industry standards and regulations (e.g., GDPR, HIPAA) concerning data protection and disaster recovery.

    8. Continuous Improvement:
       - Review post-mortem reports from actual incidents and recovery drills to identify areas for improvement.
       - Ensure that feedback loops are in place for continuous enhancement of the DR plan and procedures.
       - Confirm that lessons learned from incidents and drills are incorporated into the DR plan.

    9. Regular Updates and Communication:
       - Ensure the DR plan is reviewed and updated at least annually or whenever significant changes occur in the IT environment.
       - Verify that all relevant personnel are trained on the DR procedures and aware of their roles.
       - Check that regular communication channels are established for DR updates and training sessions.
  "
  desc  'fix', "
    1. Keep a disaster recovery plan that names the roles, the decision authority for
       declaring a disaster, and the recovery and failback procedures - and review it
       on a defined cycle rather than after an incident.
    2. Confirm the technical configuration still matches the plan: AWS Backup plans
       cover the resources the plan assumes, replication is healthy for every source
       server, and retention satisfies the stated recovery point objective.
    3. Re-test after material change. A plan validated against last year's
       architecture is not evidence for this year's.
    4. Retain drill results, review records and sign-off as the evidence for this
       control, since the state it asserts is procedural rather than API-visible.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.9'
  tag cis_rid:               '6.9'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0609r1_rule'
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
  # override else attestation_uri(:boundary, 'C-6.9'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_9_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.9') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure Continuous Disaster Recovery Operations (attestation-required)' do
      skip "attestation-required: 'Ensure Continuous Disaster Recovery Operations' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_9_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.9 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end