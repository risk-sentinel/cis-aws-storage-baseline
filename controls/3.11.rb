# encoding: UTF-8

control 'C-3.11' do
  title 'Ensure accessing Points and IAM Policies'
  desc  "
    You can use IAM policies to control access to your EFS access points. To achieve this, utilize the `elasticfilesystem:AccessPointArn` IAM condition key. The `AccessPointArn` represents the Amazon Resource Name (ARN) of the access point that the file system is mounted with.

    The rationale for using IAM policies with the `elasticfilesystem:AccessPointArn` condition key is to ensure precise and secure access control to EFS access points. By specifying the access point's ARN, you can restrict interactions to authorized users and resources only, thereby enhancing data security and preventing unauthorized access. This approach maintains the integrity and confidentiality of your data within the AWS environment.
  "
  desc  'rationale', "
    You can use IAM policies to control access to your EFS access points. To achieve this, utilize the `elasticfilesystem:AccessPointArn` IAM condition key. The `AccessPointArn` represents the Amazon Resource Name (ARN) of the access point that the file system is mounted with.

    The rationale for using IAM policies with the `elasticfilesystem:AccessPointArn` condition key is to ensure precise and secure access control to EFS access points. By specifying the access point's ARN, you can restrict interactions to authorized users and resources only, thereby enhancing data security and preventing unauthorized access. This approach maintains the integrity and confidentiality of your data within the AWS environment.
  "
  desc  'check', "
    Below is a same IAM policy copied from the AWS documentation:
    ```
    {
        \"Version\": \"2012-10-17\",
        \"Id\": \"MyFileSystemPolicy\",
        \"Statement\": [
            {
                \"Sid\": \"App1Access\",
                \"Effect\": \"Allow\",
                \"Principal\": { \"AWS\": \"arn:aws:iam::111122223333:role/app1\" },
                \"Action\": [
                    \"elasticfilesystem:ClientMount\",
                    \"elasticfilesystem:ClientWrite\"
                ],
                \"Condition\": {
                    \"StringEquals\": {
                        \"elasticfilesystem:AccessPointArn\":\"arn:aws:elasticfilesystem:us-east-1:222233334444:access-point/fsap-01234567\"
                    }
                }
            },
            {
                \"Sid\": \"App2Access\",
                \"Effect\": \"Allow\",
                \"Principal\": { \"AWS\": \"arn:aws:iam::111122223333:role/app2\" },
                \"Action\": [
                    \"elasticfilesystem:ClientMount\",
                    \"elasticfilesystem:ClientWrite\"
                ],
                \"Condition\": {
                    \"StringEquals\": {
                        \"elasticfilesystem:AccessPointArn\":\"arn:aws:elasticfilesystem:us-east  1:222233334444:access-point/fsap-89abcdef\"
                    }
                }
            }
        ]
    }
    ```
  "
  desc  'fix', "
    Control access at the file system, not only at the network.

    1. Attach a file system policy that denies any access not using TLS and not
       authenticated by IAM:

        ```
        aws efs put-file-system-policy --file-system-id <fs-id> --policy file://policy.json
        ```

       The policy should grant `elasticfilesystem:ClientMount` and `ClientWrite`
       only to the roles that need them, and include a condition denying requests
       where `aws:SecureTransport` is false.
    2. Use EFS access points to pin each application to its own directory, POSIX
       user and group, so one workload cannot read another's files even when both
       can mount the file system.
    3. Mount with the `iam` and `tls` options so the client actually presents its
       role identity over an encrypted channel.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-2 c', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 c', 'AC-3']
  tag cci:                   ['CCI-000213', 'CCI-002113', 'CCI-000051']
  tag cis_number:            '3.11'
  tag cis_rid:               '3.11'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0311r1_rule'
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
  # override else attestation_uri(:boundary, 'C-3.11'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_3_11_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-3.11') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure accessing Points and IAM Policies (attestation-required)' do
      skip "attestation-required: 'Ensure accessing Points and IAM Policies' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_3_11_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-3.11 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end