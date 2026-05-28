# Prerequisites: MwsTokenBroker module installed to a PSModulePath location
# (private binary module, not on PSGallery — build it from the zMSALModule repo)
Import-Module MwsTokenBroker

# Create GDAPGraphClient Class
. ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Classes/GDAPGraphClient.ps1" -UseBasicParsing).Content))
# Import 'CommonHelpers' module
New-Module -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Modules/CommonHelpers.psm1" -UseBasicParsing).Content)) -Name CommonHelpers | Import-Module

# Authenticate operator (interactive on first run, silent thereafter)
$MsalToken = Get-MWSOperatorToken

# Create client with operator token
$client = [GDAPGraphClient]::new($MsalToken)
