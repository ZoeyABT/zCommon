#Requires -Version 7.4
# Automatable verification for the MSAL.PS -> MwsTokenBroker migration.
# Does NOT acquire a real token (never calls the broker). Checks the module
# source (deprecated functions / MSAL.PS references removed) and the exported
# command surface, plus the missing-module guard.

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\Modules\CommonHelpers.psm1'
$moduleSource = Get-Content -Raw -Path $modulePath

function Assert-True($condition, $message) {
    if (-not $condition) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}

# 1. Deprecated functions are removed from the module source
Assert-True ($moduleSource -notmatch 'function\s+Initialize-MsalModule') `
    'Initialize-MsalModule function is removed from source'
Assert-True ($moduleSource -notmatch 'function\s+Get-KeyVaultSecrets') `
    'Get-KeyVaultSecrets function is removed from source'

# 2. No lingering MSAL.PS references in the module source
Assert-True ($moduleSource -notmatch 'MSAL\.PS') `
    'No MSAL.PS references remain in source'
Assert-True ($moduleSource -notmatch 'Get-MsalToken') `
    'No Get-MsalToken references remain in source'

# Load the module to inspect the exported surface
Import-Module $modulePath -Force

# 3. Public surface is intact
Assert-True ($null -ne (Get-Command Get-MWSOperatorToken -ErrorAction SilentlyContinue)) `
    'Get-MWSOperatorToken is exported'
Assert-True ($null -ne (Get-Command New-GDAPClient -ErrorAction SilentlyContinue)) `
    'New-GDAPClient is exported'

# 4. Deprecated helper is no longer exported
Assert-True ($null -eq (Get-Command Get-KeyVaultSecrets -ErrorAction SilentlyContinue)) `
    'Get-KeyVaultSecrets is not exported'

# 5. Missing-module guard throws (isolated child: PSModulePath has only $PSHOME\Modules,
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
