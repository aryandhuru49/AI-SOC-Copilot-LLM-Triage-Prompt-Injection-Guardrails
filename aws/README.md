# Part B — Tier 3: real AWS, $0

Everything here must stay on the **always-free** tier. Do the guardrails FIRST.

## 0. Guardrails (before anything else)

1. **AWS Budgets** → create a `$0` (or `$1`) monthly budget with an email alert at the
   first cent. Console → Billing → Budgets.
2. **CloudWatch billing alarm** at `$1` in `us-east-1`.
3. Pick ONE region and stick to it (`AWS_REGION` in `.env`).
4. Create an **IAM user** (not root) with programmatic keys and only:
   `cloudtrail:LookupEvents`, plus (if you deploy the optional Lambda/DynamoDB)
   scoped `lambda:*`, `dynamodb:*`, `sns:*` on resources tagged `project=soc-copilot`.
5. `aws configure` with those keys.

## 1. CloudTrail ingest (no cost, no infra)

```bash
pip install boto3
python aws/cloudtrail_ingest.py --hours 24
```

Uses `cloudtrail:LookupEvents` on the last 90 days of **management events** — the free
"Event history". No trail, no S3 bucket, no data events. Feed the resulting alerts into
`pipeline.triage.triage_alert` exactly like synthetic ones.

## 2. Optional: deploy the copilot as Lambda + DynamoDB (still $0)

Terraform for this goes in `aws/deploy/` (not scaffolded yet — milestone 6). Only
always-free services: Lambda (1M req/mo), DynamoDB (25 GB), SNS (1M/mo).
**Never** add: NAT Gateway, GuardDuty, Security Hub, Inspector, AWS Config rules,
Fargate/ECS, CloudTrail data events or Lake.

## 3. Always tear down

```bash
terraform destroy    # if you deployed anything
```
