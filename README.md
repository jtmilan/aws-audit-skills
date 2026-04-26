# aws-audit-skills

AWS audit skill pack — 4 independent Claude Code skills for security + hygiene checks.

Each skill is self-contained (no cross-imports between skills). All skills follow
the same shape: `skills/<name>/SKILL.md` + a single Python module that takes
CLI args, hits AWS read-only APIs, prints a markdown report.

## Skills

Each skill has its own subdirectory under `skills/` and its own usage doc under `docs/`:

- `skills/iam-policy-audit/` — flags wildcard actions, stale roles, inline policies. See `docs/iam-policy-audit.md`.
- `skills/s3-public-bucket-scan/` — flags public buckets via ACL, policy, BPA. See `docs/s3-public-bucket-scan.md`.
- `skills/vpc-flow-anomaly/` — flags traffic anomalies, DROP-list matches, gaps. See `docs/vpc-flow-anomaly.md`.
- `skills/cloudtrail-suspicious-events/` — flags console-login anomalies, off-hours key creation, mass deletes, trail-tampering. See `docs/cloudtrail-suspicious-events.md`.

## Install

```bash
git clone https://github.com/jtmilan/aws-audit-skills ~/aws-audit-skills
cd ~/aws-audit-skills
bash install.sh
```

`install.sh` symlinks every directory under `skills/` into `~/.claude/skills/`.
Adding a new skill = drop a new dir under `skills/`, re-run `install.sh`. No
edits to install.sh required.

## Test

Each skill has its own pytest suite under its own directory:

```bash
pytest skills/<name>/
```

All tests must run offline (mocked AWS via `botocore.stub.Stubber` or `moto`).

## License

Apache 2.0
