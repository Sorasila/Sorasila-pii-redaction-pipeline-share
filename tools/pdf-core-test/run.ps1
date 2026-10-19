param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArguments
)

# Python selection: PDF_CORE_TEST_PYTHON when set, otherwise the repository .venv
# (install tools/pdf-core-test/requirements.txt into it first).
$pdfTestPython = $env:PDF_CORE_TEST_PYTHON
if (-not $pdfTestPython) {
    $pdfTestPython = Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $pdfTestPython -PathType Leaf)) {
    Write-Error 'Python not found. Create the repository .venv (see README.md) or set PDF_CORE_TEST_PYTHON.'
    exit 1
}
& $pdfTestPython (Join-Path $PSScriptRoot 'pdf_to_pipeline.py') @ScriptArguments
exit $LASTEXITCODE
