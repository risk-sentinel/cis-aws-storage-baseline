# encoding: UTF-8

control 'C-6.10' do
  title 'Ensure execution of a Disaster Recovery Failover'
  desc  "
    Execute a comprehensive disaster recovery failover to transition operations from the primary system to a backup system during disruptions. This process includes ensuring all critical data and applications are accurately replicated to the backup site for seamless operational continuity. Regularly test and document the failover process to identify and resolve any issues, maintaining readiness to minimize downtime and data loss during real disasters.

    Executing a comprehensive disaster recovery failover is essential to ensure operational continuity during disruptions. Accurate replication of critical data and applications to the backup site guarantees that business operations can continue seamlessly. Regular testing and documentation of the failover process help identify and resolve potential issues, maintaining a state of readiness and minimizing downtime and data loss in actual disaster scenarios.
  "
  desc  'rationale', "
    Execute a comprehensive disaster recovery failover to transition operations from the primary system to a backup system during disruptions. This process includes ensuring all critical data and applications are accurately replicated to the backup site for seamless operational continuity. Regularly test and document the failover process to identify and resolve any issues, maintaining readiness to minimize downtime and data loss during real disasters.

    Executing a comprehensive disaster recovery failover is essential to ensure operational continuity during disruptions. Accurate replication of critical data and applications to the backup site guarantees that business operations can continue seamlessly. Regular testing and documentation of the failover process help identify and resolve potential issues, maintaining a state of readiness and minimizing downtime and data loss in actual disaster scenarios.
  "
  desc  'check', "
    Follow the steps where we learned how to conduct a recovery drill with the below modifications:
    1. Choose the server that you want to recover and failover. On the initiate recovery job menu, choose \"initiate recovery.\"
    2. Choose a point in time to recover from backup.
    3. Choose initiate recovery to create a recovery job.
    ```
    Note: You can use the job details to monitor the progress and status of the recovery job.
    ```
    After the recovery job has completed, the last recovery result of your source server will report \"successful.\"
    The EC2 instance ID of the launched recovery instance will also be listed in the source server overview.
    You can test if the recovery instance is functioning by testing the EC2 instance that is in the source server overview.
  "
  desc  'fix', "
    Failover differs from a drill in that it is authorised, and it cuts over.

    1. Confirm the declaration authority named in the disaster recovery plan has
       authorised the failover.
    2. Select the source servers and initiate a recovery job, choosing the recovery
       point deliberately - the most recent point may post-date the event that caused
       the failover.
    3. Verify the recovered instances are reachable, the application is serving, and
       dependent services (DNS, certificates, secrets, database endpoints) point at
       the recovered environment rather than the failed one.
    4. Record the actual recovery time and recovery point achieved, and keep
       replication running toward the recovery Region so the environment is itself
       protected while operating in the failed-over state.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.10'
  tag cis_rid:               '6.10'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0610r1_rule'
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
  # override else attestation_uri(:boundary, 'C-6.10'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_6_10_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-6.10') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure execution of a Disaster Recovery Failover (attestation-required)' do
      skip "attestation-required: 'Ensure execution of a Disaster Recovery Failover' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_6_10_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-6.10 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end