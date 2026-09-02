# Build the Lambda deployment zip: linux deps + app code + handlers.
# Output: aws/deploy/dist/lambda.zip   (referenced by main.tf)
$ErrorActionPreference = "Stop"

$here = $PSScriptRoot
$repo = Split-Path (Split-Path $here)
$dist = Join-Path $here "dist"
$build = Join-Path $dist "build"

Remove-Item -Recurse -Force $build, (Join-Path $dist "lambda.zip") -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $build | Out-Null

Write-Host "==> pip install (linux wheels) -> $build" -ForegroundColor Cyan
# boto3/botocore are already in the Lambda runtime; don't bundle them.
python -m pip install --target $build --platform manylinux2014_x86_64 --python-version 3.12 `
  --implementation cp --only-binary=:all: --upgrade `
  anthropic pydantic python-dotenv
if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed"; exit 1 }

Write-Host "==> copy app code" -ForegroundColor Cyan
foreach ($pkg in "pipeline", "defense", "data") {
  Copy-Item -Recurse -Force (Join-Path $repo $pkg) (Join-Path $build $pkg)
}
Copy-Item -Force (Join-Path $repo "aws/lambda/handler_triage.py") $build
Copy-Item -Force (Join-Path $repo "aws/lambda/handler_ingest.py") $build

# strip only __pycache__ — KEEP *.dist-info (importlib.metadata reads version
# info from it at import time; httpx2/anthropic fail without it).
Get-ChildItem -Recurse -Force $build -Include "__pycache__" -Directory |
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "==> zip -> $dist\lambda.zip" -ForegroundColor Cyan
# Compress-Archive writes backslash paths that break imports on Lambda (Linux).
# Use Python's zipfile with forward-slash arcnames instead.
$zipPy = @'
import zipfile, os, sys
root, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dp, _, fns in os.walk(root):
        for fn in fns:
            full = os.path.join(dp, fn)
            z.write(full, os.path.relpath(full, root).replace(os.sep, "/"))
print("lambda.zip =", round(os.path.getsize(out)/1048576, 1), "MB")
'@
$zipPy | python - $build (Join-Path $dist "lambda.zip")
if ($LASTEXITCODE -ne 0) { Write-Error "zip failed"; exit 1 }
