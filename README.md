# AWS Storage Services CIS Baseline

InSpec / CINC Auditor profile validating an AWS account against **CIS AWS Storage Services Benchmark v1.0.0**.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target.
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target.
- Azure and other cloud providers — out of scope.

Per-control partition applicability lives in
`partition_applicability.yml` and is mirrored on each control via
`tag applicable_partitions: [...]`. Controls not applicable to the
running partition skip (impact 0.0) via `only_if`; they do not fail.

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1

docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-aws-storage --overwrite
```

Execute against AWS Commercial:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-storage \
  --input aws_partition=aws \
  --reporter cli json:/src/hdf.json
```

For GovCloud, switch the partition input and region:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-gov-west-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-storage \
  --input aws_partition=aws-us-gov \
  --reporter cli json:/src/hdf.json
```

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from
the XCCDF's DISA CCI identifiers via Heimdall's
`CciNistMappingData.ts`. Provenance chain:

```
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder **fails loudly** if any rule has a CCI that is not
present in the map — we never ship controls with CCI-only tags.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_aws_storage_services_benchmark_v100.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-aws-storage \
  --profile-name cis-aws-storage \
  --profile-title "AWS Storage Services CIS Baseline" \
  --supports-platform aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

Currently scaffolded — every `describe` body is `skip 'TODO[scaffolder]: …'`.
See the top-level `README.md` for the overall repo state and the
sub-issue tracker for per-profile describe-fill progress.

---

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-storage-v1.0.0)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-storage-v1.0.0)
