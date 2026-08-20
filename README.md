# cis-aws-storage-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-storage-v1.0.0)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-storage-v1.0.0)

InSpec / CINC Auditor profile validating an AWS account against the
**CIS AWS Storage Services Benchmark v1.0.0** — 56 controls across S3, EBS, EFS,
FSx, Backup and the storage-adjacent IAM and KMS surface.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target
- Azure and other cloud providers — out of scope

Per-control partition applicability lives in
[`partition_applicability.yml`](partition_applicability.yml) and is mirrored on
each control as `tag applicable_partitions:`. Controls that do not apply to the
running partition **skip at impact 0.0** rather than failing.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-aws-storage-baseline
cd cis-aws-storage-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**. cinc-auditor does not auto-load a
profile-root inputs file, and several controls scope themselves out on an empty
input — so leaving it off produces a quieter run, not a failing one.

### Credentials

Standard AWS credential resolution. The identity needs read-only access across
the storage surface:

```
s3:GetBucket*  s3:ListAllMyBuckets  s3:GetEncryptionConfiguration
ec2:DescribeVolumes  ec2:DescribeSnapshots  ec2:DescribeRegions
elasticfilesystem:Describe*   fsx:Describe*
backup:List*  backup:Get*   kms:DescribeKey  iam:GetRole
```

No control reads object **contents**. This profile assesses configuration.

### What a first run looks like

Against a real account, with the attestation bases left empty:

**56 controls, 91 results — roughly 35 passed / 7 failed / 49 skipped.**

**The 49 skips are expected, not a broken scan.** They are the attestation-gated
controls described below. If you see far *fewer* than 91 results, that is the
signal to investigate — a run that assessed nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Scoping** | `scan_regions` — empty means every region via `ec2:DescribeRegions`; pin it to where you deploy |
| **Attestation** | `boundary_docs_base`, `leveraged_evidence_base`, `policy_provider_base`, `attestation_max_age_days` |

**49 of 56 controls are attestation-gated.** They assess things no storage API
can answer — a documented retention decision, a reviewed lifecycle policy, an
approved encryption standard. With no evidence base configured they skip with a
rationale rather than passing. Setting `boundary_docs_base` is what turns those
skips into assessed controls, and it is the single highest-value input here.

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-aws-storage-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      profile_name: cis-aws-storage-v1.0.0
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-storage-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      profile_name: cis-aws-storage-v1.0.0
      profile_version: "0.1.0"
```

An `include:` brings YAML and nothing else, so the logic lives in the YAML rather
than in a script an including project would not have.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-aws-storage-v1.0.0
    git: https://github.com/risk-sentinel/cis-aws-storage-baseline.git
    tag: v0.1.4
```

Then `include_controls 'cis-aws-storage-v1.0.0'` and supply your own inputs.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real account before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
