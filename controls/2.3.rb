# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure the proper configuration of EBS storage'
  desc  "
    All computer instances need to have a device on which to store files. EBS is built on top of EC2 instances as a block storage device.

    Remember that we are working with cloud computing. Rather than purchasing and manually installing disk drives on a server, AWS allows you to virtually add storage using Elastic Block Store (EBS).
  "
  desc  'rationale', "
    All computer instances need to have a device on which to store files. EBS is built on top of EC2 instances as a block storage device.

    Remember that we are working with cloud computing. Rather than purchasing and manually installing disk drives on a server, AWS allows you to virtually add storage using Elastic Block Store (EBS).
  "
  desc  'check', "
    This control is satisfied by a documented evidence record rather than by an API
    assertion, so the profile checks that the record exists and is current rather
    than inspecting live configuration.

    Point `boundary_docs_base` (or the per-control attestation input) at the
    evidence record, then confirm the record shows:

    - the standard EBS configuration applied to instances in scope: encryption by
      default, the KMS key used, volume type, and the `DeleteOnTermination` posture
      for root and data volumes;
    - how that standard is enforced for new volumes rather than applied by hand;
    - the date of the most recent review.

    The control fails if the record is missing, unreachable, or older than
    `attestation_max_age_days`.
  "
  desc  'fix', "
    1. Open the Amazon EC2 Console: Navigate to the EC2 Dashboard in the AWS Management Console.

    2. Select Volumes: Under the \"Elastic Block Store\" section, select \"Volumes\".

    3. Create Volume:
       - Click on \"Create Volume\".
       - Choose the volume type (e.g., General Purpose SSD (gp2), Provisioned IOPS SSD (io1), etc.).
       - Specify the size and availability zone.
       - Optionally, configure additional settings such as IOPS, encryption, and tags.

    4. Attach Volume to Instance:
       - Select the volume you created.
       - Click on \"Actions\" and choose \"Attach Volume\".
       - Select the instance to which you want to attach the volume and specify the device name.

    5. Format and Mount the Volume (on the instance):
       - Connect to your instance using SSH.
       - List available disks using the command: `lsblk`.
       - Format the new volume (e.g., `sudo mkfs -t ext4 /dev/xvdf` for ext4 filesystem).
       - Create a mount point (e.g., `sudo mkdir /mnt/data`).
       - Mount the volume (e.g., `sudo mount /dev/xvdf /mnt/data`).

    6. Configure Automatic Mounting (optional):
       - Edit the `/etc/fstab` file to add an entry for the new volume to ensure it mounts automatically on reboot.
       - Example entry: `/dev/xvdf /mnt/data ext4 defaults,nofail 0 2`.

    By following these steps, you can effectively configure and manage EBS storage for your AWS instances.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-18 a', 'CP-2 a 1']
  tag ksi:                   ['KSI-RPL-ARP']
  tag nist_r4:               ['AC-18 a', 'CP-2 a 1']
  tag cci:                   ['CCI-002323', 'CCI-000443']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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
  # override else attestation_uri(:boundary, 'C-2.3'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_2_3_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-2.3') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure the proper configuration of EBS storage (attestation-required)' do
      skip "attestation-required: 'Ensure the proper configuration of EBS storage' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_2_3_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-2.3 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end