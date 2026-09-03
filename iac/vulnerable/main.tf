# Intentionally vulnerable Terraform — a static-scan target ONLY.
# Do NOT `terraform apply` this. Checkov / tfsec / Trivy read it as text.

resource "aws_s3_bucket" "public_data" {
  bucket = "soc-copilot-demo-public-bucket"
  # CKV_AWS_20 / CKV_AWS_18 — no encryption, no logging
}

resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "wide_open" {
  name        = "allow-all"
  description = "intentionally bad"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CKV_AWS_24
  }
}

resource "aws_db_instance" "unencrypted" {
  identifier          = "soc-copilot-demo-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_encrypted   = false # CKV_AWS_16
  publicly_accessible = true  # CKV_AWS_17
  username            = "admin"
  password            = "hunter2" # CKV_SECRET — hardcoded secret
  skip_final_snapshot = true
}
