# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure creating snapshots of EBS volumes'
  desc  "
    A snapshot is a backup of your EBS volume that captures its state at a specific point in time, storing only the data changes since the last snapshot to optimize storage costs and speed. Snapshots are crucial for data recovery, creating new EBS volumes, and replicating data across AWS regions for disaster recovery and high availability. Restoring from a snapshot allows you to create a new EBS volume and attach it to an EC2 instance in the same availability zone, ensuring data integrity and accessibility.

    The rationale behind using EBS snapshots is to ensure efficient and cost-effective data backup and recovery. By capturing only the data changes since the last snapshot, storage costs are minimized and the backup process is expedited. Snapshots are essential for maintaining data integrity, facilitating quick recovery, and enabling seamless data replication across regions, thereby enhancing disaster recovery capabilities and operational resilience.
  "
  desc  'rationale', "
    A snapshot is a backup of your EBS volume that captures its state at a specific point in time, storing only the data changes since the last snapshot to optimize storage costs and speed. Snapshots are crucial for data recovery, creating new EBS volumes, and replicating data across AWS regions for disaster recovery and high availability. Restoring from a snapshot allows you to create a new EBS volume and attach it to an EC2 instance in the same availability zone, ensuring data integrity and accessibility.

    The rationale behind using EBS snapshots is to ensure efficient and cost-effective data backup and recovery. By capturing only the data changes since the last snapshot, storage costs are minimized and the backup process is expedited. Snapshots are essential for maintaining data integrity, facilitating quick recovery, and enabling seamless data replication across regions, thereby enhancing disaster recovery capabilities and operational resilience.
  "
  desc  'check', "
    To audit the use of EBS snapshots in AWS, follow these steps:

    1. Access the AWS Management Console:
       - Log in to your AWS account and navigate to the AWS Management Console.

    2. Review EBS Snapshots:
       - Go to the EC2 Dashboard and select \"Snapshots\" under the \"Elastic Block Store\" section.
       - Check the list of snapshots to ensure regular backups are being created for all critical volumes.

    3. Verify Snapshot Policies:
       - Ensure that snapshot lifecycle policies are in place and configured correctly.
       - Go to the \"Lifecycle Manager\" under the EC2 Dashboard and review policies for automated snapshot creation and retention.

    4. Check Snapshot Status and Details:
       - Review the status of each snapshot to ensure they are completed successfully.
       - Verify the details of snapshots, such as description, creation time, and the volume ID associated with each snapshot.

    5. Inspect IAM Policies and Permissions:
       - Navigate to the IAM Dashboard and review the policies attached to users, groups, and roles.
       - Ensure that only authorized personnel have permissions to create, delete, and manage snapshots.

    6. Use AWS Config Rules:
       - Enable AWS Config to continuously monitor and record AWS resource configurations.
       - Create AWS Config rules to check for compliance with best practices, such as ensuring snapshots are created regularly and are not older than a specific period.

    7. Review AWS CloudTrail Logs:
       - Use AWS CloudTrail to review logs of API calls related to EBS snapshots.
       - Ensure that all snapshot activities are logged and can be traced back to authorized users and roles.

    8. Generate Reports:
       - Utilize AWS Config and AWS CloudTrail to generate compliance and activity reports.
       - Review these reports to ensure adherence to snapshot policies and identify any anomalies or unauthorized activities.

    By following these steps, you can effectively audit the use of EBS snapshots to ensure data integrity, security, and compliance with best practices.
  "
  desc  'fix', "
    To create an EBS snapshot on AWS, follow these steps:

    1. Access the AWS Management Console:
       - Log in to your AWS account and navigate to the AWS Management Console.

    2. Navigate to the EC2 Dashboard:
       - In the AWS Management Console, select \"EC2\" from the services menu to open the EC2 Dashboard.

    3. Select the Volume:
       - In the left-hand navigation pane, under \"Elastic Block Store,\" click on \"Volumes.\"
       - Find the volume you want to snapshot from the list and select it by clicking the checkbox next to it.

    4. Create a Snapshot:
       - With the volume selected, click on the \"Actions\" button at the top of the page.
       - From the dropdown menu, select \"Create Snapshot.\"

    5. Configure the Snapshot:
       - In the \"Create Snapshot\" dialog box, provide a description for the snapshot. This helps identify the snapshot later.
       - Review the volume ID to ensure it is the correct volume.

    6. Initiate the Snapshot Creation:
       - Click the \"Create Snapshot\" button to start the snapshot creation process.

    7. Monitor the Snapshot:
       - Navigate to the \"Snapshots\" section under \"Elastic Block Store\" in the left-hand navigation pane.
       - Find your snapshot in the list and monitor its status. The snapshot creation process might take some time, depending on the size of the volume and the amount of data.

    8. Verify Completion:
       - Once the snapshot status changes to \"completed,\" it indicates that the snapshot has been successfully created and is available for use.

    By following these steps, you can create an EBS snapshot to ensure you have a backup of your volume at a specific point in time.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0205r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.5'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_5_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.5') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure creating snapshots of EBS volumes (attestation-required)' do
      skip "attestation-required: 'Ensure creating snapshots of EBS volumes' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_5_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.5 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end