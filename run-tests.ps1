$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

$PreviousPythonPath = $env:PYTHONPATH
$ProjectSrc = Join-Path $ProjectRoot "src"
if ([string]::IsNullOrWhiteSpace($PreviousPythonPath)) {
    $env:PYTHONPATH = $ProjectSrc
} else {
    $env:PYTHONPATH = "$ProjectSrc$([IO.Path]::PathSeparator)$PreviousPythonPath"
}

python -m unittest discover -s tests -v
$TestExitCode = $LASTEXITCODE

if ($null -eq $PreviousPythonPath) {
    Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
} else {
    $env:PYTHONPATH = $PreviousPythonPath
}

if ($TestExitCode -ne 0) {
    exit $TestExitCode
}
