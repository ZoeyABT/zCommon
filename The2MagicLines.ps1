# Prerequisites: Install-Module MSAL.PS -Scope CurrentUser
Import-Module MSAL.PS

# Create GDAPGraphClient Class
. ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Classes/GDAPGraphClient.ps1" -UseBasicParsing).Content))
# Import 'CommonHelpers' module
New-Module -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Modules/CommonHelpers.psm1" -UseBasicParsing).Content)) -Name CommonHelpers | Import-Module

# Authenticate operator (interactive on first run, silent thereafter)
$MsalToken = Get-MWSOperatorToken

# Create client with operator token
$client = [GDAPGraphClient]::new($MsalToken)
