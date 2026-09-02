variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "soc-copilot"
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
  # Supplied via TF_VAR_anthropic_api_key (see aws/deploy/apply.sh). Never committed.
}

variable "triage_model" {
  type    = string
  default = "claude-sonnet-5"
}

variable "guard_model" {
  type    = string
  default = "claude-haiku-4-5"
}

variable "alert_email" {
  type        = string
  default     = ""
  description = "If set, subscribes this address to high/critical SNS notifications."
}
