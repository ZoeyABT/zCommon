<#
.SYNOPSIS
    Common helper functions for GDAPGraphClient-based projects

.DESCRIPTION
    Reusable utility functions including:
    - MWS API operator authentication via the MwsTokenBroker WAM module
    - Graph API pagination handling
    - Common patterns for multi-tenant operations

.NOTES
    Author: ABT Engineering
    Version: 3.0
    Dependencies: MwsTokenBroker (private binary module; install to a PSModulePath location)
#>

<#
.SYNOPSIS
    Acquire an MWS API operator token via the MwsTokenBroker WAM module

.DESCRIPTION
    Authenticates the operator against the MWS API app registration using the
    MwsTokenBroker module (Get-MwsBrokerToken), which acquires tokens through the
    Windows WAM broker with MSAL isolated in a private AssemblyLoadContext. The
    broker attempts silent acquisition first (from its persisted cache) and falls
    back to an interactive WAM prompt on first use or when the cached token expires.

    The returned token object exposes AccessToken and ExpiresOn and is used as the
    bearer token for all GDAPGraphClient token proxy calls.

.PARAMETER ForceInteractive
    Skip silent acquisition and force an interactive WAM login

.OUTPUTS
    Token object with AccessToken (string) and ExpiresOn (DateTimeOffset)

.EXAMPLE
    $msalToken = Get-MWSOperatorToken
    $client = [GDAPGraphClient]::new($msalToken)

.EXAMPLE
    # Force re-authentication
    $msalToken = Get-MWSOperatorToken -ForceInteractive

.NOTES
    - Requires the MwsTokenBroker module (private binary module, NOT on PSGallery).
      Install it to a PSModulePath location before use.
    - Cannot be used inside PowerShell classes (cmdlet injection limitation)
    - Tokens are cached by the broker; subsequent calls use silent refresh
#>
function Get-MWSOperatorToken {
    [CmdletBinding()]
    param(
        [switch]$ForceInteractive
    )

    if (-not (Get-Module -ListAvailable -Name MwsTokenBroker)) {
        throw @"
The 'MwsTokenBroker' module is required but was not found.
It is a private binary module (not on PSGallery) and must be installed to a PSModulePath location.
Build it from the zMSALModule repo and copy the 'module' output into one of your PSModulePath folders.
"@
    }

    Import-Module MwsTokenBroker -ErrorAction Stop

    $token = Get-MwsBrokerToken -ForceInteractive:$ForceInteractive
    Write-Verbose "Acquired MWS operator token (expires: $($token.ExpiresOn))"
    return $token
}

<#
.SYNOPSIS
    Handle Graph API pagination automatically (Graph API v1.0/beta)

.DESCRIPTION
    Automatically follows @odata.nextLink to retrieve all pages of results.
    Works specifically with Microsoft Graph API pagination structure.

.PARAMETER GraphClient
    Instance of GDAPGraphClient configured for Graph API

.PARAMETER Uri
    Initial Graph API endpoint URL

.PARAMETER Method
    HTTP method (typically "GET")

.PARAMETER Body
    Optional request body for POST/PATCH operations

.OUTPUTS
    Array of all items from all pages combined

.EXAMPLE
    $usersUri = "https://graph.microsoft.com/v1.0/users"
    $allUsers = Get-GraphRequestWithPaging -GraphClient $graphClient -Uri $usersUri

.EXAMPLE
    $devicesUri = "https://graph.microsoft.com/beta/devices"
    $allDevices = Get-GraphRequestWithPaging -GraphClient $graphClient -Uri $devicesUri -Method "GET"

.NOTES
    - Only works with Microsoft Graph API (not Azure ARM or Partner Center)
    - Looks for 'value' array and '@odata.nextLink' in response
    - Use Get-AzureRequestWithPaging for Azure Resource Manager API
    - Use Get-PartnerCenterRequestWithPaging for Partner Center API
#>
function Get-GraphRequestWithPaging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$GraphClient,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "Get",

        [Parameter(Mandatory = $false)]
        [object]$Body = $null
    )

    $allResults = [System.Collections.ArrayList]::new()
    $currentUri = $Uri
    $pageCount = 0

    do {
        $pageCount++
        Write-Verbose "Fetching page $pageCount from: $currentUri"

        $response = $GraphClient.GraphAPICall($currentUri, $Method, $Body)

        # Check for errors
        if ($null -eq $response -or $response.StatusCode -ge 300) {
            Write-Warning "Request failed with status code: $($response.StatusCode)"
            break
        }

        # Extract items from 'value' array
        if ($null -ne $response.Content) {
            if ($response.Content.PSObject.Properties.Name -contains 'value') {
                $pageItems = $response.Content.value
                if ($null -ne $pageItems) {
                    if ($pageItems -is [array]) {
                        [void]$allResults.AddRange($pageItems)
                        Write-Verbose "Added $($pageItems.Count) items from page $pageCount"
                    } else {
                        [void]$allResults.Add($pageItems)
                        Write-Verbose "Added 1 item from page $pageCount"
                    }
                }
            } else {
                # No 'value' property means single object response or error
                Write-Verbose "No 'value' array in response, stopping pagination"
                $currentUri = $null
                break
            }

            # Check for next page link
            if ($response.Content.PSObject.Properties.Name -contains '@odata.nextLink' -and
                -not [string]::IsNullOrEmpty($response.Content.'@odata.nextLink')) {
                $currentUri = $response.Content.'@odata.nextLink'
                Write-Verbose "Next page link found, continuing..."
            } else {
                Write-Verbose "No more pages, pagination complete"
                $currentUri = $null
            }
        } else {
            Write-Verbose "Empty response content, stopping pagination"
            $currentUri = $null
        }

    } while ($currentUri)

    Write-Verbose "Pagination complete. Total items retrieved: $($allResults.Count) across $pageCount pages"
    return @($allResults)
}

<#
.SYNOPSIS
    Handle Azure Resource Manager API pagination

.DESCRIPTION
    Azure ARM API uses 'nextLink' (not @odata.nextLink) for pagination.
    Automatically follows nextLink to retrieve all pages.

.PARAMETER GraphClient
    Instance of GDAPGraphClient configured for Azure ARM (with delegated token)

.PARAMETER Uri
    Initial Azure ARM endpoint URL

.PARAMETER Method
    HTTP method (typically "GET")

.OUTPUTS
    Array of all items from all pages combined

.EXAMPLE
    $subscriptionsUri = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    $allSubs = Get-AzureRequestWithPaging -GraphClient $azClient -Uri $subscriptionsUri

.EXAMPLE
    $vmsUri = "https://management.azure.com/subscriptions/$subId/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01"
    $allVMs = Get-AzureRequestWithPaging -GraphClient $azClient -Uri $vmsUri

.NOTES
    - Only works with Azure Resource Manager API
    - Looks for 'value' array and 'nextLink' in response
    - Requires delegated token (GetGDAPToken with Azure scope)
#>
function Get-AzureRequestWithPaging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$GraphClient,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "Get"
    )

    $allResults = [System.Collections.ArrayList]::new()
    $currentUri = $Uri
    $pageCount = 0

    do {
        $pageCount++
        Write-Verbose "Fetching Azure ARM page $pageCount from: $currentUri"

        $response = $GraphClient.GraphAPICall($currentUri, $Method)

        if ($null -eq $response -or $response.StatusCode -ge 300) {
            Write-Warning "Azure ARM request failed with status code: $($response.StatusCode)"
            break
        }

        if ($null -ne $response.Content) {
            if ($response.Content.PSObject.Properties.Name -contains 'value') {
                $pageItems = $response.Content.value
                if ($null -ne $pageItems) {
                    if ($pageItems -is [array]) {
                        [void]$allResults.AddRange($pageItems)
                        Write-Verbose "Added $($pageItems.Count) items from Azure ARM page $pageCount"
                    } else {
                        [void]$allResults.Add($pageItems)
                        Write-Verbose "Added 1 item from Azure ARM page $pageCount"
                    }
                }
            } else {
                Write-Verbose "No 'value' array in Azure ARM response, stopping pagination"
                $currentUri = $null
                break
            }

            # Azure ARM uses 'nextLink' (not @odata.nextLink)
            if ($response.Content.PSObject.Properties.Name -contains 'nextLink' -and
                -not [string]::IsNullOrEmpty($response.Content.nextLink)) {
                $currentUri = $response.Content.nextLink
                Write-Verbose "Azure ARM next page link found, continuing..."
            } else {
                Write-Verbose "No more Azure ARM pages, pagination complete"
                $currentUri = $null
            }
        } else {
            Write-Verbose "Empty Azure ARM response content, stopping pagination"
            $currentUri = $null
        }

    } while ($currentUri)

    Write-Verbose "Azure ARM pagination complete. Total items: $($allResults.Count) across $pageCount pages"
    return @($allResults)
}

<#
.SYNOPSIS
    Handle Partner Center API pagination

.DESCRIPTION
    Partner Center API uses 'links.next.uri' and requires MS-ContinuationToken header.
    Automatically follows pagination to retrieve all pages.

.PARAMETER GraphClient
    Instance of GDAPGraphClient configured for Partner Center (GetCSPToken)

.PARAMETER Uri
    Initial Partner Center endpoint URL

.PARAMETER Method
    HTTP method (typically "GET")

.OUTPUTS
    Array of all items from all pages combined

.EXAMPLE
    $customersUri = "https://api.partnercenter.microsoft.com/v1/customers"
    $allCustomers = Get-PartnerCenterRequestWithPaging -GraphClient $cspClient -Uri $customersUri

.EXAMPLE
    $subscriptionsUri = "https://api.partnercenter.microsoft.com/v1/customers/$customerId/subscriptions"
    $allSubs = Get-PartnerCenterRequestWithPaging -GraphClient $cspClient -Uri $subscriptionsUri

.NOTES
    - Only works with Partner Center API
    - Looks for 'items' array, 'links.next.uri', and 'continuationtoken'
    - Requires CSP token (GetCSPToken)
#>
function Get-PartnerCenterRequestWithPaging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$GraphClient,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "Get"
    )

    $allResults = [System.Collections.ArrayList]::new()
    $currentUri = $Uri
    $pageCount = 0
    $continueHeader = $null

    do {
        $pageCount++
        Write-Verbose "Fetching Partner Center page $pageCount from: $currentUri"

        $response = $GraphClient.GraphAPICall($currentUri, $Method, $continueHeader)

        if ($null -eq $response -or $response.StatusCode -ge 300) {
            Write-Warning "Partner Center request failed with status code: $($response.StatusCode)"
            break
        }

        if ($null -ne $response.Content) {
            # Partner Center uses 'items' array (not 'value')
            if ($response.Content.PSObject.Properties.Name -contains 'items') {
                $pageItems = $response.Content.items
                if ($null -ne $pageItems) {
                    if ($pageItems -is [array]) {
                        [void]$allResults.AddRange($pageItems)
                        Write-Verbose "Added $($pageItems.Count) items from Partner Center page $pageCount"
                    } else {
                        [void]$allResults.Add($pageItems)
                        Write-Verbose "Added 1 item from Partner Center page $pageCount"
                    }
                }
            } else {
                Write-Verbose "No 'items' array in Partner Center response, stopping pagination"
                $currentUri = $null
                break
            }

            # Partner Center uses 'links.next.uri' and requires continuation token header
            if ($response.Content.PSObject.Properties.Name -contains 'links' -and
                $response.Content.links.PSObject.Properties.Name -contains 'next' -and
                -not [string]::IsNullOrEmpty($response.Content.links.next.uri)) {

                # Build next URI (relative path from Partner Center)
                $currentUri = "https://api.partnercenter.microsoft.com/v1" + $response.Content.links.next.uri

                # Set continuation token header for next request
                if ($response.Content.PSObject.Properties.Name -contains 'continuationtoken') {
                    $continueHeader = @{ 'MS-ContinuationToken' = "$($response.Content.continuationtoken)" }
                }

                Write-Verbose "Partner Center next page link found, continuing..."
            } else {
                Write-Verbose "No more Partner Center pages, pagination complete"
                $currentUri = $null
            }
        } else {
            Write-Verbose "Empty Partner Center response content, stopping pagination"
            $currentUri = $null
        }

    } while ($currentUri)

    Write-Verbose "Partner Center pagination complete. Total items: $($allResults.Count) across $pageCount pages"
    return @($allResults)
}

<#
.SYNOPSIS
    Create an authenticated GDAPGraphClient instance

.DESCRIPTION
    Factory function that handles MwsTokenBroker operator authentication and returns
    a ready-to-use GDAPGraphClient. All scripts should use this single entry
    point for client creation — if the auth flow changes in the future, only
    this function needs to be updated.

.PARAMETER ForceInteractive
    Skip silent broker acquisition and force an interactive WAM login

.OUTPUTS
    GDAPGraphClient instance with MsalToken set, ready for Get*Token calls

.EXAMPLE
    $client = New-GDAPClient
    $client.GetCSPToken($client.APIScopes.PartnerCenter)

.EXAMPLE
    $client = New-GDAPClient
    $client.GetGDAPToken($customerTenantId, $client.APIScopes.GraphAPI)

.EXAMPLE
    $client = New-GDAPClient -ForceInteractive
#>
function New-GDAPClient {
    [CmdletBinding()]
    param(
        [switch]$ForceInteractive
    )

    $msalToken = Get-MWSOperatorToken -ForceInteractive:$ForceInteractive
    $client = [GDAPGraphClient]::new($msalToken)
    return $client
}

# Export functions
Export-ModuleMember -Function @(
    'New-GDAPClient',
    'Get-MWSOperatorToken',
    'Get-GraphRequestWithPaging',
    'Get-AzureRequestWithPaging',
    'Get-PartnerCenterRequestWithPaging'
)
