# encoding: UTF-8

control 'C-3.10' do
  title 'Ensure managing AWS EFS access points'
  desc  "
    EFS access points serve as gateways to your EFS file system, allowing applications to interact with the file system across various resources. Proper configuration of these access points within your applications is crucial to ensure seamless and secure access. By configuring EFS access points, you can control and manage which users have access to specific resources in your EFS environment, enhancing security and operational efficiency.

    The rationale behind properly configuring EFS access points is to ensure secure and efficient interaction between your applications and the EFS file system. By setting up these access points correctly, you can control and manage user permissions, ensuring that only authorized users can access specific resources. This not only enhances the security of your data but also improves operational efficiency by preventing unauthorized access and potential data breaches.
  "
  desc  'rationale', "
    EFS access points serve as gateways to your EFS file system, allowing applications to interact with the file system across various resources. Proper configuration of these access points within your applications is crucial to ensure seamless and secure access. By configuring EFS access points, you can control and manage which users have access to specific resources in your EFS environment, enhancing security and operational efficiency.

    The rationale behind properly configuring EFS access points is to ensure secure and efficient interaction between your applications and the EFS file system. By setting up these access points correctly, you can control and manage user permissions, ensuring that only authorized users can access specific resources. This not only enhances the security of your data but also improves operational efficiency by preventing unauthorized access and potential data breaches.
  "
  desc  'check', "
    1. Creating an EFS access point:
    You can create an EFS access point through the amazon CLI, AWS console, and with the EFS API. An EFS can only have up to 1,000 access points.
    2. Mounting an EFS access point:
    Consult the section where we mounted an EFS file system on an EC2 instance.
    While inside the resource you want to configure an access point for, type in this command: 
    ```
    mount -t efs -o tls,iam,accesspoint=fsap-abcdef0123456789a fs-abc0123def456789a: /localmountpoint
    ```
    3. Enforcing a User Identity with an EFS access point:
    You can enforce user identity to ensure that users and groups with proper permissions are able to access the EFS file system. In order to do this, you must specify the user and group ID you wish to have ownership of the files.
    When ```enforcement ``` is enabled, that file that is was created by the user  will automatically show ownership to belong to the user. When enforcement is enabled, the access point considers the User ID, group ID, and secondary group ID. It ignored the NFS client's ID. 
    ```
    Note: enforcing the user ID is subject to the \"ClientRootAccess\" IAM permission. If either the User ID or Group ID = 0, then you must explicitly allow \"ClientRootAccess\" permission.
    ```
    4. Enforcing a root directory with an access point:
    If you wish to override the root directory of the EFS, you can make the root directory that of the access point. To enforce the root directory with an access point, you must specify three things upon provisioning the EFS mount point:
    	- Owner UID
    	- Group GID
    	- Permissions
    To access an EFS from an access point, a root directory must be created and enforced. Reminder: You must specify permissions for the access point root directory. If these permissions are not defined, a root directory will not be created on the mount point, and you will not be able to access EFS from an access point. 
    5. Security Model for access point root directories:
    When a root directory override is in effect, the EFS behaves like a Linux server with a no_subtree_check option enabled.
  "
  desc  'fix', "
    Implement AWS EFS access points
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.10'
  tag cis_rid:               '3.10'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0310r1_rule'
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

  describe 'Ensure managing AWS EFS access points' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0310r1_rule.'
  end
end
