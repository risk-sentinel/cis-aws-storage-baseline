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
    TODO: check content missing in source XCCDF
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
  tag nist:                  ['AC-18 a', 'CP-2 a 1']
  tag cci:                   ['CCI-002323', 'CCI-000443']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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

  describe 'Ensure the proper configuration of EBS storage' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0203r1_rule.'
  end
end
