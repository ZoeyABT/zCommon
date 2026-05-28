#Requires -Version 7.4
# Automatable verification for the MSAL.PS -> MwsTokenBroker migration.
# Does NOT acquire a real token (never calls the broker); only checks the
# exported command surface and the missing-module guard.

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\Modules\CommonHelpers.psm1'

function Assert-True($condition, $message) {
    if (-not $condition) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}

# Load the module in this session
Import-Module $modulePath -Force

# 1. Deprecated helpers are gone
Assert-True ($null -eq (Get-Command Initialize-MsalModule -ErrorAction SilentlyContinue)) `
    'Initialize-MsalModule is removed'
Assert-True ($null -eq (Get-Command Get-KeyVaultSecrets -ErrorAction SilentlyContinue)) `
    'Get-KeyVaultSecrets is removed'

# 2. Public surface is intact
Assert-True ($null -ne (Get-Command Get-MWSOperatorToken -ErrorAction SilentlyContinue)) `
    'Get-MWSOperatorToken is exported'
Assert-True ($null -ne (Get-Command New-GDAPClient -ErrorAction SilentlyContinue)) `
    'New-GDAPClient is exported'

# 3. Missing-module guard throws (isolated child: PSModulePath has only $PSHOME\Modules,
#    so MwsTokenBroker cannot be found even if installed on this machine).
$childScript = @'
$ErrorActionPreference = "Stop"
$empty = (New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("emptymods_" + [guid]::NewGuid())) -Force).FullName
$env:PSModulePath = (Join-Path $PSHOME "Modules") + [IO.Path]::PathSeparator + $empty
Import-Module "{0}" -Force
try {{
    Get-MWSOperatorToken -ErrorAction Stop
    Write-Output "NO_THROW"
}} catch {{
    if ($_.Exception.Message -match "MwsTokenBroker") {{ Write-Output "THREW_OK" }}
    else {{ Write-Output ("WRONG_MSG:" + $_.Exception.Message) }}
}}
'@ -f $modulePath

$result = pwsh -NoProfile -Command $childScript
Assert-True ($result -eq 'THREW_OK') `
    "Get-MWSOperatorToken throws a MwsTokenBroker guidance error when the module is absent (got: $result)"

Write-Host "`nAll migration checks passed." -ForegroundColor Cyan
