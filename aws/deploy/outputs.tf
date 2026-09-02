output "triage_function_url" {
  description = "HTTPS endpoint for the triage Lambda (requires SigV4-signed requests)."
  value       = aws_lambda_function_url.triage.function_url
}

output "dynamodb_table" {
  value = aws_dynamodb_table.alerts.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.high_sev.arn
}

output "ingest_function" {
  value = aws_lambda_function.ingest.function_name
}
