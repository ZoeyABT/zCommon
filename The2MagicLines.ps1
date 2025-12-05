#Create GDAPGraphClient Class
. ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Classes/GDAPGraphClient.ps1" -UseBasicParsing).Content))
#Import 'CommonHelpers' module
New-Module -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Modules/CommonHelpers.psm1" -UseBasicParsing).Content)) -Name CommonHelpers | Import-Module