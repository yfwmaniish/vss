# PowerShell wrapper for VSS scanner to use the correct Python interpreter
param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$pythonExe = "C:\Users\manis\AppData\Local\Programs\Python\Python310\python.exe"

if (-not (Test-Path $pythonExe)) {
    Write-Error "Python 3.10 not found at $pythonExe"
    exit 1
}

Write-Host "Using Python: $pythonExe" -ForegroundColor Green
& $pythonExe "vss.py" @Arguments
