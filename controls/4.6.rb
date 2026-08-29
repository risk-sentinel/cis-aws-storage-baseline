# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure EC2 Kernel compatibility with Lustre'
  desc  "
    The latest kernel included with the Ubuntu Amazon EC2 AMI is not compatible with the Lustre service, which is crucial for mounting the cache on your EC2 instance. To downgrade your kernel, specific prerequisites must be met if you are using the default Ubuntu machine image as of November 8, 2023.

    The latest kernel version is not supported by Lustre, and meeting the prerequisites for downgrading will allow you to leverage Lustre's high-performance file system capabilities effectively. This ensures optimal data access and processing efficiency on your EC2 instance.
  "
  desc  'rationale', "
    The latest kernel included with the Ubuntu Amazon EC2 AMI is not compatible with the Lustre service, which is crucial for mounting the cache on your EC2 instance. To downgrade your kernel, specific prerequisites must be met if you are using the default Ubuntu machine image as of November 8, 2023.

    The latest kernel version is not supported by Lustre, and meeting the prerequisites for downgrading will allow you to leverage Lustre's high-performance file system capabilities effectively. This ensures optimal data access and processing efficiency on your EC2 instance.
  "
  desc  'check', "
    Follow the steps to downgrade your kernel:
    1. List all of the available Lustre packages by typing in this command: sudo apt-cache search lustre-client-modules. This will show a list of supported modules with corresponding kernel versions in ascending order from top to bottom. The most recent version in this case is \"lustre-client-modules-5.15.0-1049-aws. Save this information for the next commands.
    2. Install the most recent linux image that supports the Lustre client with this command: 
    ```
    sudo apt-get install -y linux-image-5.15.0-1049-aws
    sudo sed -i 's/GRUB_DEFAULT=.\\+/GRUB\\_DEFAULT=\"Advanced options for Ubuntu>Ubuntu, with Linux 5.15.0-1049-aws\"/' /etc/default/grub
    ```
    3. Reboot your system by typing \"sudo reboot\".
    4. Install the correct Lustre module: .
    ```
    sudo apt-get install -y lustre-client-modules-$(uname -r)
    ```
  "
  desc  'fix', "
    Match the kernel and the Lustre client rather than downgrading the kernel.

    Downgrading to an older kernel to satisfy a client module reintroduces every
    kernel vulnerability patched since that release, and the instance will drift
    back on the next update. Prefer, in order:

    1. Install the `lustre-client-modules-aws` metapackage, which tracks the current
       AWS-supported kernel, so client and kernel advance together.
    2. If no client build exists for the current kernel, pin the instance to the most
       recent kernel that does have one, and treat that pin as a tracked exception
       with a review date - not a permanent state.
    3. Only if neither is possible, select an AMI whose shipped kernel is supported
       by the client, rather than downgrading a running host.

    Confirm the result is a supported pair, and that unattended upgrades will not
    silently move the kernel past the client again.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-5 (1) (e)', 'AC-2 c', 'SI-4 (5)', 'SI-4 a 1']
  tag cci:                   ['CCI-000200', 'CCI-002113', 'CCI-002663', 'CCI-001253']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS AWS Storage Services Benchmark v1.0.0'
  tag cis_rule_id:           'SV-0406r1_rule'
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
  # override else attestation_uri(:boundary, 'C-4.6'); empty -> Skip (stays
  # saf attest apply-able). category policy.
  uri = input('c_4_6_attestation_uri', value: '')
  uri = attestation_uri(:boundary, 'C-4.6') if uri.to_s.empty?
  max_age_days = input('attestation_max_age_days', value: 365)
  if uri.to_s.empty?
    describe 'Ensure EC2 Kernel compatibility with Lustre (attestation-required)' do
      skip "attestation-required: 'Ensure EC2 Kernel compatibility with Lustre' is a setup/operational procedure not assertable via the AWS API. Set boundary_docs_base / c_4_6_attestation_uri to the configuration/operational evidence record, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.6 evidence (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end