data "aws_caller_identity" "current" {}

locals {
  name       = var.project
  account_id = data.aws_caller_identity.current.account_id
  # build_lambda.(ps1|sh) produces this zip: deps + pipeline/ defense/ data/ + handlers
  lambda_zip = "${path.module}/dist/lambda.zip"
}

# --------------------------------------------------------------------------
# Secret: Anthropic API key in SSM Parameter Store (SecureString) — FREE.
# (Secrets Manager would bill $0.40/mo per secret; Parameter Store standard is $0.)
# --------------------------------------------------------------------------
resource "aws_ssm_parameter" "anthropic_key" {
  name  = "/${local.name}/anthropic_api_key"
  type  = "SecureString"
  value = var.anthropic_api_key
}

# --------------------------------------------------------------------------
# Storage: one DynamoDB table for alerts + triage results (on-demand, 25GB free)
# --------------------------------------------------------------------------
resource "aws_dynamodb_table" "alerts" {
  name         = "${local.name}-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_id"

  attribute {
    name = "alert_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true # AWS-owned key ($0); CMK (CKV_AWS_119) intentionally not used
  }
}

# --------------------------------------------------------------------------
# Notifications: SNS topic, optional email subscription
# --------------------------------------------------------------------------
resource "aws_sns_topic" "high_sev" {
  name              = "${local.name}-high-severity"
  kms_master_key_id = "alias/aws/sns" # AWS-managed key, $0 (CKV_AWS_26)
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.high_sev.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --------------------------------------------------------------------------
# IAM: one execution role for both Lambdas, least privilege
# --------------------------------------------------------------------------
resource "aws_iam_role" "lambda_exec" {
  name = "${local.name}-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_exec" {
  name = "${local.name}-lambda-policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.region}:${local.account_id}:*"
      },
      {
        Sid      = "Dynamo"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = aws_dynamodb_table.alerts.arn
      },
      {
        Sid      = "ReadKey"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = aws_ssm_parameter.anthropic_key.arn
      },
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.high_sev.arn
      },
      {
        Sid      = "CloudTrailRead"
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
      {
        Sid      = "InvokeTriage"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = "arn:aws:lambda:${var.region}:${local.account_id}:function:${local.name}-triage"
      }
    ]
  })
}

# --------------------------------------------------------------------------
# Lambda: triage + guardrails
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${local.name}-triage"
  retention_in_days = 3
}

resource "aws_lambda_function" "triage" {
  function_name                  = "${local.name}-triage"
  role                           = aws_iam_role.lambda_exec.arn
  runtime                        = "python3.12"
  handler                        = "handler_triage.handler"
  filename         = local.lambda_zip
  source_code_hash = filebase64sha256(local.lambda_zip)
  timeout          = 60
  memory_size      = 512
  # No reserved_concurrent_executions: this account's total concurrency limit is
  # too low (<=10) for AWS to allow any reservation. Cost is bounded by the budget
  # alarm instead. (CKV_AWS_115 accepted in .checkov.yaml.)

  tracing_config {
    mode = "Active" # X-Ray; free tier covers this (CKV_AWS_50)
  }

  environment {
    variables = {
      DDB_TABLE     = aws_dynamodb_table.alerts.name
      SNS_TOPIC_ARN = aws_sns_topic.high_sev.arn
      SSM_KEY_NAME  = aws_ssm_parameter.anthropic_key.name
      TRIAGE_MODEL  = var.triage_model
      GUARD_MODEL   = var.guard_model
    }
  }
  depends_on = [aws_cloudwatch_log_group.triage]
}

resource "aws_lambda_function_url" "triage" {
  function_name      = aws_lambda_function.triage.function_name
  authorization_type = "AWS_IAM" # signed requests only — it is a security project
}

# --------------------------------------------------------------------------
# Lambda: CloudTrail ingest (pulls real events, writes alerts, invokes triage)
# --------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "ingest" {
  name              = "/aws/lambda/${local.name}-ingest"
  retention_in_days = 3
}

resource "aws_lambda_function" "ingest" {
  function_name                  = "${local.name}-ingest"
  role                           = aws_iam_role.lambda_exec.arn
  runtime                        = "python3.12"
  handler                        = "handler_ingest.handler"
  filename         = local.lambda_zip
  source_code_hash = filebase64sha256(local.lambda_zip)
  timeout          = 120
  memory_size      = 512
  # See triage function: account concurrency limit too low to reserve.

  tracing_config {
    mode = "Active" # X-Ray; free tier covers this (CKV_AWS_50)
  }

  environment {
    variables = {
      DDB_TABLE          = aws_dynamodb_table.alerts.name
      TRIAGE_FUNCTION    = aws_lambda_function.triage.function_name
      CLOUDTRAIL_HOURS   = "1"
    }
  }
  depends_on = [aws_cloudwatch_log_group.ingest]
}

# --------------------------------------------------------------------------
# EventBridge: run the ingest Lambda hourly
# --------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "hourly" {
  name                = "${local.name}-hourly-ingest"
  schedule_expression = "rate(1 hour)"
  # Kept DISABLED on purpose: the pipeline runs only on manual invocation.
  # To resume the hourly CloudTrail ingest, set state = "ENABLED" (or run
  #   aws events enable-rule --name soc-copilot-hourly-ingest --profile soc-copilot
  # ) and `terraform apply`.
  state = "DISABLED"
}

resource "aws_cloudwatch_event_target" "hourly" {
  rule = aws_cloudwatch_event_rule.hourly.name
  arn  = aws_lambda_function.ingest.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.hourly.arn
}
