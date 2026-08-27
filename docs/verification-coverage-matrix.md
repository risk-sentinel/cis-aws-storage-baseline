# cis-aws-storage — verification coverage matrix

Profile authored from `cis_aws_storage_services_benchmark_v100.xml`
with the #154 evidence-class model (#168). Built on its own merit per
`each_profile_stands_alone` (S3 overlap with cis-aws-foundations §3 is NOT a reason
to skip). Principle: verify what the AWS API can assert; attest the rest, honestly.

**The benchmark's nature:** the XCCDF `check-content` is overwhelmingly console
how-to / setup tutorials and operational exercises (create/install/mount/export,
recovery drill, failover, failback) — not machine-assertable state. So most controls
are genuinely procedural/operational (→ attestation, NOT fabricated checks).

| Disposition | Count | Meaning |
|---|---|---|
| `implemented` (verified) | 7 | Real inspec-aws assertion |
| `alternative` — policy attestation | 28 | Config/setup record (`:boundary` document_attestation) |
| `alternative` — operational attestation | 21 | Setup step / periodic operational exercise |

## Verified (implemented)

| Control | Check |
|---|---|
| C-1.6 Backup service-linked role | `aws_iam_role('AWSServiceRoleForBackup')` exists |
| C-2.2 EC2/EBS security groups | no SG allows `0.0.0.0/0` on SSH (22) |
| C-2.4 EBS volume encryption | every `aws_ebs_volume` is encrypted |
| C-2.11 IAM password policy | length ≥14 + symbol/number/upper/lower required |
| C-3.6 EFS secure ports | no SG allows `0.0.0.0/0` on NFS (2049) |
| C-5.1 S3 default encryption | every bucket has default encryption |
| C-5.2 S3 public access | no bucket is public |

## Attestation — why (not fabricated checks)

The remaining 49 controls' check-content is setup/operational procedure with no
AWS-API-assertable state:
- **policy (28)** — configuration/setup records (backup plans, IAM policy design,
  EFS/FSx/S3 setup, DR configuration). `document_attestation(:boundary)` against the
  consumer's config-evidence record; empty → Skip (`saf attest apply`-able).
- **operational (21)** — point-in-time exercises / installs (recovery drill, failover,
  failback, replication-agent install, Lustre client install/mount/export, "EDR working").
  Genuinely not assertable from API state — `document_attestation`/`saf attest apply`.

Each attestation has a per-control `c_<id>_attestation_uri` override + a freshness floor.
Where automation later becomes feasible (e.g., DRS replication config, CloudWatch alarm
presence) those can be promoted to `implemented` in a follow-up.

`exec_validated: false` — the 7 verified controls' inspec-aws logic is not yet exec'd
against a live account (no creds here); validate before relying on a FAIL.
