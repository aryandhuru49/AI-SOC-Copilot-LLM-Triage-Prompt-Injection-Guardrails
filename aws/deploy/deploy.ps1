# Deploy the SOC Copilot stack: build zip -> terraform apply.
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File .\aws\deploy\deploy.ps1
$ErrorActionPreference = "Stop"

$PROFILE_NAME = "soc-copilot"
$TFDIR        = $PSScriptRoot
$CD           = "-chdir=$TFDIR"
$REPO         = Split-Path (Split-Path $PSScriptRoot)
Set-Location $REPO

function Check($m) { if ($LASTEXITCODE -ne 0) { Write-Error $m; exit 1 } }

# terraform on PATH?
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
  $env:PATH += ";$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe"
}
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) { Write-Error "terraform not found"; exit 1 }

# Anthropic key from .env -> terraform variable
$keyLine = Select-String -Path ".env" -Pattern '^ANTHROPIC_API_KEY=' | Select-Object -First 1
if (-not $keyLine) { Write-Error "ANTHROPIC_API_KEY not found in .env"; exit 1 }
$env:TF_VAR_anthropic_api_key = ($keyLine.Line -replace '^ANTHROPIC_API_KEY=', '').Trim().Trim('"')
$env:AWS_PROFILE = $PROFILE_NAME

Write-Host "==> 1/3  build lambda.zip" -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File (Join-Path $TFDIR "build_lambda.ps1"); Check "build_lambda failed"

Write-Host "==> 2/3  terraform init + apply" -ForegroundColor Cyan
terraform $CD init "-input=false";                     Check "init failed"
terraform $CD apply "-input=false" "-auto-approve";    Check "apply failed"

Write-Host "==> 3/3  outputs" -ForegroundColor Cyan
terraform $CD output
