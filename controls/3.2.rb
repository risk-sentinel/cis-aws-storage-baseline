# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure Implementation of EFS'
  desc  "
    AWS EFS is a fully managed storage service that enables rapid file system deployment without the need for configuration, patching, or maintenance.

    The rationale behind using AWS EFS is to simplify and expedite the deployment of file systems, eliminating the need for manual configuration, patching, and maintenance. This allows you to focus on other critical aspects of your operations while benefiting from a reliable, scalable, and fully managed storage solution.
  "
  desc  'rationale', "
    AWS EFS is a fully managed storage service that enables rapid file system deployment without the need for configuration, patching, or maintenance.

    The rationale behind using AWS EFS is to simplify and expedite the deployment of file systems, eliminating the need for manual configuration, patching, and maintenance. This allows you to focus on other critical aspects of your operations while benefiting from a reliable, scalable, and fully managed storage solution.
  "
  desc  'check', "
    1. Navigate to console - https://us-east-1.console.aws.amazon.com/efs/home?region=us-east-1#/get-started.
    2. Select \"Create File System\". Give the file system a name and select the default VPC. Select \"Create\".
    3. Encrypting data at rest - The EFS is encrypted automatically upon creation..
    4. Attach the EFS to an EC2 instance.
    5. Navigate to file system details - Select the radio box next to the file system that was just created and select \"view details\".
    6. Creating an NFS directory on your EC2 instance - Launch your EC2 instance. Once connected, Type following command: 
    ```\"sudo mkdir efs\"```
    to create a new efs directory.
    7. Mounting an NFS directory on your EC2 instance - Navigate to find your EC2 DNS information
    Paste this command into the console after making the efs directory
    ```
    sudo mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport mount-target-DNS:/   ~/efs-mount-point ```
 
    NOTE: The encryption takes place as soon as you mount the directory. This encrypts the data in transit.
    8. Terminating the EC2 instance - The EFS file system that was just mounted doesn't persist on reboot. You can consult the AWS documentation to see how you can write a script to automatically mount the file system upon every reboot.
  "
  desc  'fix', "
    To remediate the issues of manual file system management, follow these steps to create and use Amazon EFS:

    1. Open the Amazon EFS Console: Sign in to the AWS Management Console and navigate to the Amazon EFS service.
    2. Create a New File System: Click on \"Create file system\" to start the setup process.
    3. Configure Settings: Select your desired VPC, availability zones, throughput mode, and any additional settings like lifecycle management.
    4. Set Up Access Points: Configure access points to control permissions and simplify access management.
    5. Review and Create: Verify your settings and click \"Create\" to finalize the file system setup.
    6. Mount the File System: Use the provided mount targets and instructions to attach the file system to your EC2 instances or other resources.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'IA-5 (1) (e)', 'AU-4', 'SI-4 (5)']
  tag cci:                   ['CCI-001199', 'CCI-000200', 'CCI-001848', 'CCI-002663']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0302r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.2'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_3_2_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.2') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure Implementation of EFS (attestation-required)' do
      skip "attestation-required: 'Ensure Implementation of EFS' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_2_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.2 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end