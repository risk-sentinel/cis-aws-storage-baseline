# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure mounting FSx cache'
  desc  "
    Mounting the FSx cache is a crucial step to optimize data retrieval and system performance. This process involves connecting the FSx file system to your compute instances, allowing them to access cached data efficiently. Properly mounting the FSx cache ensures low-latency access to frequently used data, enhances overall application performance, and leverages the full capabilities of the AWS FSx service. This setup is essential for achieving high performance and efficient data processing in your AWS environment.

    By connecting the FSx file system to your compute instances, you enable low-latency access to frequently used data, significantly improving application performance. This setup leverages the full capabilities of the AWS FSx service, ensuring efficient data processing and resource utilization in your AWS environment. Properly mounting the FSx cache is essential for achieving high performance and operational efficiency.
  "
  desc  'rationale', "
    Mounting the FSx cache is a crucial step to optimize data retrieval and system performance. This process involves connecting the FSx file system to your compute instances, allowing them to access cached data efficiently. Properly mounting the FSx cache ensures low-latency access to frequently used data, enhances overall application performance, and leverages the full capabilities of the AWS FSx service. This setup is essential for achieving high performance and efficient data processing in your AWS environment.

    By connecting the FSx file system to your compute instances, you enable low-latency access to frequently used data, significantly improving application performance. This setup leverages the full capabilities of the AWS FSx service, ensuring efficient data processing and resource utilization in your AWS environment. Properly mounting the FSx cache is essential for achieving high performance and operational efficiency.
  "
  desc  'check', "
    To mount your cache, follow the next steps:
    1. Make a directory for the mount point with the following command:
    ```
    sudo mkdir -p /mnt
    ```
    2. Mount the Amazon file cache to the directory that you just created. Use the following command and replace these names:
    	- Replace cache_dns_name with the actual file cache's Domain Name System (DNS) name
    	- Replace mountname with the cache's mount name, which you can get by running the describe-file-caches AWS CLI command or DescribeFileCaches API operation 
    ```
    sudo mount -t lustre -o relatime,flock cache_dns_name@tcp:/mountname /mnt
    ```
    Note: Make sure your EC2 instance is in the same VPC as your cache.
    If done correctly, the path of your folder will show up in the /mnt folder.

    You can also use the df command to see the DNS and mount point is attached to your file system:
  "
  desc  'fix', "
    Mount the cache so the transport and the client's identity are both constrained.

    1. Mount using the cache's DNS name and mount name, from an instance in the
       cache's VPC:

        ```
        sudo mount -t lustre -o relatime,flock <cache-dns-name>@tcp:/<mountname> /mnt/cache
        ```

    2. Add the mount to `/etc/fstab` with `_netdev` so a reboot does not leave the
       workload running against an empty directory.
    3. Mount on a path owned by the service account that uses it, and avoid mounting
       at `/mnt` itself where any local user can traverse it.
    4. Confirm the instance reaches the cache over private addressing, not through a
       public route.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'IA-5 (1) (e)', 'AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-000213', 'CCI-000200', 'CCI-001682', 'CCI-001848']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0407r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.7'); empty -> Skip (stays
  # saf attest apply-able). category operational.
  uri = input('c_4_7_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.7') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure mounting FSx cache (attestation-required)' do
      skip "attestation-required: 'Ensure mounting FSx cache' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_7_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.7 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end