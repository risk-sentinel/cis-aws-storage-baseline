# encoding: UTF-8

control 'C-6.1' do
  title 'Ensure Elastic Disaster Recovery is Configured'
  desc  "
    AWS Elastic Disaster Recovery is a service that enables you to create and maintain backups of your workloads on AWS, particularly your servers. This service is crucial for ensuring high resilience for your AWS workloads. It operates by establishing and maintaining backups in selected AWS regions, guaranteeing that your data is safe, durable, and highly available in the event of issues in the primary availability zone or region where your AWS server is located.

    AWS Elastic Disaster Recovery is crucial for establishing high resiliency in the cloud, synonymous with effective disaster recovery. High resiliency measures your organization's ability to respond to and recover from disasters impacting IT infrastructure. Achieving high resiliency minimizes downtime and long-term costs associated with outages, while low resiliency can result in prolonged downtime, potential data loss, and even permanent infrastructure damage.
  "
  desc  'rationale', "
    AWS Elastic Disaster Recovery is a service that enables you to create and maintain backups of your workloads on AWS, particularly your servers. This service is crucial for ensuring high resilience for your AWS workloads. It operates by establishing and maintaining backups in selected AWS regions, guaranteeing that your data is safe, durable, and highly available in the event of issues in the primary availability zone or region where your AWS server is located.

    AWS Elastic Disaster Recovery is crucial for establishing high resiliency in the cloud, synonymous with effective disaster recovery. High resiliency measures your organization's ability to respond to and recover from disasters impacting IT infrastructure. Achieving high resiliency minimizes downtime and long-term costs associated with outages, while low resiliency can result in prolonged downtime, potential data loss, and even permanent infrastructure damage.
  "
  desc  'check', "
    1. Review Disaster Recovery Plans:
       - Log in to the AWS Management Console.
       - Navigate to the AWS Elastic Disaster Recovery service.
       - Locate and open the disaster recovery plans.
       - Verify that the plans are current and comprehensive, covering all critical workloads.
       - Ensure that the plans specify clear recovery time objectives (RTO) and recovery point objectives (RPO).

    2. Check Backup Configurations:
       - In the AWS Elastic Disaster Recovery dashboard, review the list of protected servers and workloads.
       - Confirm that backups are enabled for all critical servers and workloads.
       - Verify the backup schedule and frequency to ensure they meet organizational requirements.
       - Check that backups are being stored in the correct AWS regions as specified in the disaster recovery plan.

    3. Test Recovery Procedures:
       - Identify a non-production environment to conduct recovery drills.
       - Initiate a simulated disaster scenario to test the recovery procedures.
       - Execute the recovery process for each critical workload.
       - Measure and document the time taken to recover each workload.
       - Compare the measured recovery times against the RTO and RPO.
       - Identify and document any issues or delays encountered during the recovery process.

    4. Monitor Backup Integrity:
       - Open the AWS CloudWatch console.
       - Set up CloudWatch Alarms to monitor the status of backups.
       - Configure alerts for any failed or incomplete backups.
       - Regularly review the CloudWatch logs to verify that backups are successfully completed and stored.

    5. Evaluate Backup Storage and Security:
       - Access the AWS S3 or Glacier console, depending on where backups are stored.
       - Verify that all backup data is encrypted in transit and at rest.
       - Check the storage settings to confirm that data is being stored in secure, durable storage solutions.
       - Review the access control policies to ensure that only authorized personnel have access to backup data.

    6. Ensure Compliance with Policies and Regulations:
       - Review organizational and regulatory compliance requirements relevant to disaster recovery.
       - Ensure that the disaster recovery practices and configurations comply with these requirements.
       - Document the compliance efforts, including any specific steps taken to meet industry standards and regulations.
       - Prepare reports or evidence of compliance for any upcoming audits or assessments.
  "
  desc  'fix', "
    1. Update Disaster Recovery Plans:
       - Action: Log in to the AWS Management Console.
       - Procedure:
         - Navigate to the AWS Elastic Disaster Recovery service.
         - Locate and review the current disaster recovery plans.
         - Update the plans to ensure they are comprehensive and cover all critical workloads.
         - Ensure that the plans specify clear recovery time objectives (RTO) and recovery point objectives (RPO).
         - Save and document the updated plans.

    2. Correct Backup Configurations:
       - Action: Verify and adjust backup settings.
       - Procedure:
         - In the AWS Elastic Disaster Recovery dashboard, review the list of protected servers and workloads.
         - Enable backups for any critical servers and workloads that are not currently being backed up.
         - Adjust the backup schedule and frequency to meet organizational requirements.
         - Ensure backups are stored in the correct AWS regions as specified in the disaster recovery plan.

    3. Conduct Recovery Procedure Drills:
       - Action: Test and refine recovery procedures.
       - Procedure:
         - Identify a non-production environment to conduct recovery drills.
         - Simulate a disaster scenario to test the recovery procedures.
         - Execute the recovery process for each critical workload.
         - Measure and document the time taken to recover each workload.
         - Compare the measured recovery times against the RTO and RPO.
         - Identify and address any issues or delays encountered during the recovery process.
         - Update the recovery procedures based on the findings from the drill.

    4. Ensure Backup Integrity:
       - Action: Monitor and verify the integrity of backups.
       - Procedure:
         - Open the AWS CloudWatch console.
         - Set up CloudWatch Alarms to monitor the status of backups.
         - Configure alerts for any failed or incomplete backups.
         - Regularly review CloudWatch logs to verify that backups are successfully completed and stored.
         - Resolve any issues identified in the logs, such as incomplete or failed backups.

    5. Enhance Backup Storage and Security:
       - Action: Improve the storage and security of backup data.
       - Procedure:
         - Access the AWS S3 or Glacier console, depending on where backups are stored.
         - Ensure all backup data is encrypted in transit and at rest.
         - Adjust storage settings to confirm that data is being stored in secure, durable storage solutions.
         - Review and update access control policies to ensure only authorized personnel can access backup data.
         - Implement any additional security measures necessary to protect the backup data.

    6. Ensure Compliance with Policies and Regulations:
       - Action: Align disaster recovery practices with compliance requirements.
       - Procedure:
         - Review organizational and regulatory compliance requirements relevant to disaster recovery.
         - Adjust disaster recovery practices and configurations to ensure compliance with these requirements.
         - Document the compliance efforts, including specific steps taken to meet industry standards and regulations.
         - Prepare and maintain reports or evidence of compliance for any upcoming audits or assessments.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.1'
  tag cis_rid:               '6.1'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0601r1_rule'
  tag cis_version:           '1.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe 'Ensure Elastic Disaster Recovery is Configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0601r1_rule.'
  end
end
