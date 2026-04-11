# inspec-secure-vpc — Live compliance verification for SecureVpc

InSpec profile that verifies SecureVpc zero-trust architecture against
deployed AWS infrastructure. Generic (not K3s-specific), reusable by
any cluster composing SecureVpc.

## Run

```bash
inspec exec . -t aws:// --input vpc_id=$VPC_ID vpc_name_prefix=seph
```

## Controls (10)

| ID | CIS | NIST | What |
|----|-----|------|------|
| secure-vpc-01 | 5.3 | SC-7(5) | Default SG zero rules |
| secure-vpc-02 | 5.6 | AU-2 | Flow logs enabled + delivering |
| secure-vpc-03 | — | AU-11 | Flow log retention correct |
| secure-vpc-04 | 5.1 | AC-17 | NACLs deny SSH/RDP from 0.0.0.0/0 |
| secure-vpc-05 | — | SC-7(16) | Private subnets no public IP |
| secure-vpc-06 | — | SC-7 | Route table isolation |
| secure-vpc-07 | — | SC-7 | S3 gateway endpoint present |
| secure-vpc-08 | — | AC-4 | TrustBoundary tags on all resources |
| secure-vpc-09 | 5.2 | SC-7(11) | No SG allows SSH from 0.0.0.0/0 |
| secure-vpc-10 | — | AU-6 | Flow log IAM minimal permissions |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `vpc_id` | yes | — | VPC ID to verify |
| `vpc_name_prefix` | yes | — | Resource name prefix (e.g., `seph`) |
| `expected_retention_days` | no | 7 | Flow log retention |
| `vpc_cidr` | no | 10.0.0.0/16 | Expected CIDR |
| `flow_logs_enabled` | no | true | Whether flow logs are expected |

## Integration

- `inspec-aws-k3s` can add `depends: inspec-secure-vpc` to inherit VPC controls
- `iac-test-runner` orchestrates: `inspec exec . -t aws:// --input-file outputs.json`
- Pre-deploy equivalent: kensa `fedramp-moderate-vpc.toml` profile validates
  Terraform JSON (same controls, different execution layer)

## Dependencies

InSpec >= 5.0, inspec-aws. Ruby >= 3.3, MIT.
