<#
.SYNOPSIS
    GDAPGraphClient - Universal API client for Microsoft Partner Center, Graph API, and Azure ARM

.DESCRIPTION
    A PowerShell class for making authenticated API calls to Microsoft Partner Center,
    Graph API, Azure Resource Manager, and other Microsoft APIs. Uses the MWS API token
    proxy for secure token acquisition — credentials never leave Azure.

    Requires MSAL.PS module for operator authentication.

.NOTES
    Author: ABT Engineering
    Version: 2.0
    Dependencies: MSAL.PS module

.EXAMPLE
    # Authenticate operator and create client
    Import-Module MSAL.PS
    $msalToken = Get-MWSOperatorToken
    $client = [GDAPGraphClient]::new($msalToken)

.EXAMPLE
    # Get delegated token for customer tenant Graph API
    $client.GetGDAPToken($customerTenantId, $client.APIScopes.GraphAPI)

.EXAMPLE
    # Get Partner Center token
    $client.GetCSPToken($client.APIScopes.PartnerCenter)

.EXAMPLE
    # Get app-only token for MDE
    $client.GetAppToken($customerTenantId, $client.APIScopes.MDE)
#>

class GDAPGraphClient {
    # Token state
    [string]$accesstoken
    [datetime]$expires
    [string]$tenantid
    [object]$claims

    # Configuration
    [hashtable]$APIScopes
    [PSCustomObject]$MsalToken
    [string]$MWSApiUrl = 'https://api.mortgageworkspace.com'
    [string]$CSPTenantId = '3376fd25-ade9-423f-99d5-058e6d4214c3'

    # Request behavior
    [System.Collections.ArrayList]$requesthistory
    [int]$maxretrycount = 1
    [int]$retrydelay = 5
    [int]$maxThrottleRetries = 10
    [bool]$ThrowOnRetryExhaustion = $true  # Set to $false to return error response instead of throwing

    # Auto-refresh context (set by Get*Token methods for ValidateToken)
    hidden [string]$_lastGrantType
    hidden [string]$_lastScope

    # Default constructor
    GDAPGraphClient() {
        $this._Init()
    }

    # Constructor with MSAL token
    GDAPGraphClient([PSCustomObject]$msalToken) {
        $this._Init()
        $this.MsalToken = $msalToken
    }

    # Shared initialization
    hidden [void] _Init() {
        $this.requesthistory = [System.Collections.ArrayList]::New()

        # Define available API scopes
        $this.APIScopes = @{
            GraphAPI = 'https://graph.microsoft.com/.default'
            MDE = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
            Security = 'https://api.security.microsoft.com'
            Exchange = 'https://outlook.office365.com/.default'
            Azure = 'https://management.azure.com//user_impersonation'
            PartnerCenter = 'https://api.partnercenter.microsoft.com/.default'
        }
    }

    <#
    .SYNOPSIS
        Call the MWS API token proxy to acquire a scoped access token

    .DESCRIPTION
        All token methods route through this proxy. The proxy handles KeyVault
        secret retrieval and Microsoft login via managed identity — credentials
        never leave Azure.

    .PARAMETER TenantId
        Target tenant ID for the token request

    .PARAMETER Scope
        API scope for the token request

    .PARAMETER GrantType
        OAuth grant type: 'refresh_token' (delegated) or 'client_credentials' (app-only)
    #>
    hidden [PSCustomObject] InvokeTokenProxy([string]$TenantId, [string]$Scope, [string]$GrantType) {
        $headers = @{
            Authorization  = "Bearer $($this.MsalToken.AccessToken)"
            'Content-Type' = 'application/json'
        }

        $body = @{
            tenantId  = $TenantId
            scope     = $Scope
            grantType = $GrantType
        } | ConvertTo-Json

        $response = Invoke-RestMethod `
            -Uri "$($this.MWSApiUrl)/API/EntraID/Token" `
            -Method Post `
            -Headers $headers `
            -Body $body `
            -ContentType 'application/json'

        return $response
    }

    <#
    .SYNOPSIS
        Acquire delegated token via token proxy (GDAP context)

    .DESCRIPTION
        Use this method when you need DELEGATED permissions (user context).
        Required for:
        - Azure Resource Manager API (always requires delegated)
        - Graph API calls requiring delegated permissions
        - Customer tenant operations via GDAP

    .PARAMETER tenantid
        Target tenant ID to authenticate against

    .PARAMETER scope
        API scope (use $this.APIScopes.GraphAPI, $this.APIScopes.Azure, etc.)
    #>
    [void]GetGDAPToken([string]$tenantid, [string]$scope) {
        $ProgressPreference = 'SilentlyContinue'
        $retryCount = 0

        while ($retryCount -lt $this.maxretrycount) {
            try {
                $response = $this.InvokeTokenProxy($tenantid, $scope, 'refresh_token')
                $this.accesstoken = $response.access_token
                $this.expires = (Get-Date).AddSeconds($response.expires_in)
                $this.tenantid = $tenantid
                $this._lastGrantType = 'refresh_token'
                $this._lastScope = $scope
                $this.DecodeClaims()
                $ProgressPreference = 'Continue'
                return
            }
            catch {
                $retryCount++
                if ($retryCount -ge $this.maxretrycount) {
                    $ProgressPreference = 'Continue'
                    throw "GDAPGraphClient.GetGDAPToken - Failed to acquire token via proxy! Error: $_"
                }
                Start-Sleep -Seconds $this.retrydelay
            }
        }
    }

    # Backward-compatible overload — appid, refreshtoken, clientsecret are ignored (proxy handles credentials)
    [void]GetGDAPToken([string]$appid, [string]$refreshtoken, [string]$clientsecret, [string]$tenantid, [string]$scope) {
        Write-Warning "GetGDAPToken: appid, refreshtoken, and clientsecret parameters are deprecated. The token proxy handles credentials. Use GetGDAPToken(tenantid, scope) instead."
        $this.GetGDAPToken($tenantid, $scope)
    }

    <#
    .SYNOPSIS
        Acquire application-only token via token proxy (client credentials)

    .DESCRIPTION
        Use this method when you need APPLICATION permissions (no user context).
        This is the default for most background automation scenarios.
        Cannot be used for Azure Resource Manager API (requires delegated).

    .PARAMETER tenantid
        Target tenant ID to authenticate against

    .PARAMETER scope
        API scope (use $this.APIScopes.GraphAPI, $this.APIScopes.MDE, etc.)
    #>
    [void]GetAppToken([string]$tenantid, [string]$scope) {
        $ProgressPreference = 'SilentlyContinue'
        $retryCount = 0

        while ($retryCount -lt $this.maxretrycount) {
            try {
                $response = $this.InvokeTokenProxy($tenantid, $scope, 'client_credentials')
                $this.accesstoken = $response.access_token
                $this.expires = (Get-Date).AddSeconds($response.expires_in)
                $this.tenantid = $tenantid
                $this._lastGrantType = 'client_credentials'
                $this._lastScope = $scope
                $this.DecodeClaims()
                $ProgressPreference = 'Continue'
                return
            }
            catch {
                $retryCount++
                if ($retryCount -ge $this.maxretrycount) {
                    $ProgressPreference = 'Continue'
                    throw "GDAPGraphClient.GetAppToken - Failed to acquire token via proxy! Error: $_"
                }
                Start-Sleep -Seconds $this.retrydelay
            }
        }
    }

    # Backward-compatible overload — appid, clientsecret are ignored (proxy handles credentials)
    [void]GetAppToken([string]$appid, [string]$clientsecret, [string]$tenantid, [string]$scope) {
        Write-Warning "GetAppToken: appid and clientsecret parameters are deprecated. The token proxy handles credentials. Use GetAppToken(tenantid, scope) instead."
        $this.GetAppToken($tenantid, $scope)
    }

    <#
    .SYNOPSIS
        Acquire Partner Center API token via token proxy (CSP operations)

    .DESCRIPTION
        Use this method EXCLUSIVELY for Partner Center API operations.
        The proxy handles the two-step exchange (Azure AD token → Partner Center token)
        server-side, so only a single call is needed.

    .PARAMETER scope
        Must be $this.APIScopes.PartnerCenter
    #>
    [void]GetCSPToken([string]$scope) {
        $ProgressPreference = 'SilentlyContinue'

        try {
            $response = $this.InvokeTokenProxy($this.CSPTenantId, $scope, 'refresh_token')
            $this.accesstoken = $response.access_token
            $this.expires = (Get-Date).AddSeconds($response.expires_in)
            $this.tenantid = $this.CSPTenantId
            $this._lastGrantType = 'refresh_token'
            $this._lastScope = $scope
            $ProgressPreference = 'Continue'
        }
        catch {
            $ProgressPreference = 'Continue'
            throw "GDAPGraphClient.GetCSPToken - Failed to acquire CSP token via proxy! Error: $_"
        }
    }

    # Backward-compatible overload — appid, refreshtoken, clientsecret are ignored (proxy handles credentials)
    [void]GetCSPToken([string]$appid, [string]$refreshtoken, [string]$clientsecret, [string]$scope) {
        Write-Warning "GetCSPToken: appid, refreshtoken, and clientsecret parameters are deprecated. The token proxy handles credentials. Use GetCSPToken(scope) instead."
        $this.GetCSPToken($scope)
    }

    <#
    .SYNOPSIS
        Automatically validate and refresh expired tokens via proxy

    .DESCRIPTION
        Called automatically by GraphAPICall before each request.
        Checks if token expires in <5 minutes and refreshes via the token proxy.
        If refresh context is not available, emits a warning for the caller
        to re-acquire manually via the appropriate Get*Token method.
    #>
    [void]ValidateToken() {
        $timeremaining = $this.expires - (Get-Date)

        # Refresh if less than 5 minutes remaining
        if ($timeremaining.TotalSeconds -lt 300) {
            # Check if we have enough context to auto-refresh
            if ([string]::IsNullOrEmpty($this._lastGrantType) -or
                [string]::IsNullOrEmpty($this._lastScope) -or
                [string]::IsNullOrEmpty($this.tenantid)) {
                Write-Warning "Token is expiring. Re-acquire via Get*Token method."
                return
            }

            try {
                $response = $this.InvokeTokenProxy($this.tenantid, $this._lastScope, $this._lastGrantType)
                $this.accesstoken = $response.access_token
                $this.expires = (Get-Date).AddSeconds($response.expires_in)
            }
            catch {
                Write-Warning "Token auto-refresh via proxy failed: $_. Re-acquire via Get*Token method."
            }
        }
    }

    <#
    .SYNOPSIS
        Decode JWT token to extract claims (roles/scopes)

    .DESCRIPTION
        Extracts and stores the claims from the access token.
        Claims are either 'roles' (app permissions) or 'scp' (delegated permissions).
    #>
    [void]DecodeClaims() {
        $token = $this.accesstoken
        $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')

        # Fix base64 padding
        while($tokenPayload.Length % 4) {
            $tokenPayload += "="
        }

        $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
        $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
        $tokobj = $tokenArray | ConvertFrom-Json

        if($tokobj.PSObject.Properties.Name -contains 'roles') {
            $this.claims = $tokobj.roles
        }
        elseif($tokobj.PSObject.Properties.Name -contains 'scp') {
            $this.claims = $tokobj.scp
        }
    }

    <#
    .SYNOPSIS
        Make authenticated API call with automatic retry and token validation

    .DESCRIPTION
        Primary method for all API calls. Handles:
        - Automatic token validation/refresh
        - Request retry logic (configurable via maxretrycount)
        - Throttling (429) with exponential backoff and Retry-After header support
        - Response tracking in requesthistory
        - JSON serialization of request bodies
        - Comprehensive error handling with detailed error information

    .PARAMETER Uri
        Full API endpoint URL

    .PARAMETER Method
        HTTP method (GET, POST, PATCH, PUT, DELETE)

    .PARAMETER additionalHeaders
        Optional hashtable of additional HTTP headers

    .PARAMETER body
        Request body (will be converted to JSON if not already a string)

    .OUTPUTS
        GraphAPIResponse object with statusCode, Content, Headers, etc.

        Error Handling:
        - By default, throws GraphAPIException when retries are exhausted (ThrowOnRetryExhaustion = $true)
        - Set ThrowOnRetryExhaustion = $false to return error response objects instead
        - Always check response.StatusCode >= 400 for errors
        - StatusCode = 0 indicates status code could not be extracted
        - Error details available in response.Content (typically JSON with 'error' property)

    .EXAMPLE
        $response = $client.GraphAPICall("https://graph.microsoft.com/v1.0/users", "GET")
        if ($response.StatusCode -ge 400) {
            Write-Error "Request failed: $($response.StatusDescription)"
        }

    .EXAMPLE
        $body = @{ displayName = "Test User"; userPrincipalName = "test@domain.com" }
        $response = $client.GraphAPICall("https://graph.microsoft.com/v1.0/users", "POST", $null, $body)

    .EXAMPLE
        # Handle exceptions
        try {
            $response = $client.GraphAPICall($uri, "GET")
        } catch [GraphAPIException] {
            Write-Error "API Error: $($_.Exception.Message)"
            Write-Error "Status Code: $($_.Exception.Response.StatusCode)"
            Write-Error "Error Details: $($_.Exception.Response.Content | ConvertTo-Json)"
        }
    #>
    [object]GraphAPICall($Uri, $Method, $additionalHeaders, $body) {
        # Validate token and set headers
        $this.ValidateToken()
        $Headers = @{Authorization = "Bearer $($this.accesstoken)"}

        if($null -ne $additionalHeaders) {
            $additionalHeaders.Keys | ForEach-Object {
                $Headers[$_] = $additionalHeaders[$_]
            }
        }

        # Generate unique request ID for tracking
        $requestid = [System.Guid]::NewGuid().ToString()

        # Create response object
        $response = [GraphAPIResponse]::new()
        $response.uri = $uri
        $response.RequestId = $requestid
        $ProgressPreference = 'SilentlyContinue'

        $retryCount = 0
        $throttleRetryCount = 0
        $baseDelay = $this.retrydelay

        while($retryCount -lt $this.maxretrycount) {
            Try {
                if($null -eq $body -or ([string]::IsNullOrWhiteSpace($body))) {
                    $rawresponse = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -ContentType 'Application/Json' -UseBasicParsing -ErrorAction Stop
                }
                Else {
                    # Determine request body - handle string, string array (Get-Content without -Raw), or object
                    $requestBody = $null
                    if ($body -is [string]) {
                        $requestBody = $body
                    }
                    elseif ($body -is [array] -and $body.Count -gt 0 -and ($body | ForEach-Object { $_ -is [string] }) -notcontains $false) {
                        # String array (e.g., from Get-Content without -Raw) - join into single string
                        $requestBody = $body -join "`n"
                    }
                    else {
                        # Object/hashtable - convert to JSON
                        $requestBody = $body | ConvertTo-Json -Depth 10
                    }
                    $rawresponse = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -Body $requestBody -ContentType 'Application/Json' -UseBasicParsing -ErrorAction Stop
                }

                # Success case
                $response.statusCode = $rawresponse.StatusCode
                $response.StatusDescription = $rawresponse.StatusDescription
                try {
                    $response.Content = $rawresponse.Content | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    $response.Content = $rawresponse.Content
                }
                $response.Headers = $rawresponse.Headers
                break
            }
            Catch {
                $statusCode = $null
                $retryAfter = $null
                $responseHeaders = $null
                $errorContent = $null

                # Extract status code from exception (version-agnostic approach)
                if ($_.Exception.Response) {
                    # PowerShell 5.1 and 7.x compatible
                    try {
                        # Try PowerShell 7+ approach first (direct enum)
                        if ($_.Exception.Response.StatusCode -is [System.Net.HttpStatusCode]) {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                        }
                        # PowerShell 5.1 approach (value__ property)
                        elseif ($_.Exception.Response.StatusCode.PSObject.Properties['value__']) {
                            $statusCode = [int]$_.Exception.Response.StatusCode.value__
                        }
                    } catch {
                        # Fallback: try to extract from exception message
                        if ($_.Exception.Message -match '\((\d{3})\)') {
                            $statusCode = [int]$matches[1]
                        } elseif ($_.Exception.Message -match '\b(\d{3})\b') {
                            # Try to find any 3-digit number that might be a status code
                            $potentialCodes = [regex]::Matches($_.Exception.Message, '\b(\d{3})\b')
                            foreach ($match in $potentialCodes) {
                                $code = [int]$match.Value
                                if ($code -ge 100 -and $code -lt 600) {
                                    $statusCode = $code
                                    break
                                }
                            }
                        }
                    }
                } elseif ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                    try {
                        if ($_.Exception.Response.StatusCode -is [System.Net.HttpStatusCode]) {
                            $statusCode = [int]$_.Exception.Response.StatusCode
                        }
                    } catch {
                        # Status code extraction failed
                    }
                }

                # If still no status code, check ErrorDetails (PowerShell 7+)
                if ($null -eq $statusCode -and $_.ErrorDetails) {
                    if ($_.ErrorDetails.Message -match '\((\d{3})\)') {
                        $statusCode = [int]$matches[1]
                    }
                }

                # Extract Retry-After header (version-agnostic approach)
                if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                    try {
                        $retryAfterHeader = $_.Exception.Response.Headers['Retry-After']
                        if ($retryAfterHeader) {
                            # Retry-After can be seconds (int) or HTTP date (string)
                            if ($retryAfterHeader -is [int]) {
                                $retryAfter = $retryAfterHeader
                            } elseif ($retryAfterHeader -is [string]) {
                                # Try parsing as HTTP date first
                                $parsedDate = $null
                                if ([DateTime]::TryParse($retryAfterHeader, [ref]$parsedDate)) {
                                    $retryAfter = [Math]::Max(1, [int](($parsedDate - (Get-Date)).TotalSeconds))
                                } else {
                                    # Try parsing as integer string
                                    $parsedInt = 0
                                    if ([int]::TryParse($retryAfterHeader, [ref]$parsedInt)) {
                                        $retryAfter = $parsedInt
                                    }
                                }
                            }
                        }
                    } catch {
                        # Header extraction failed, will use exponential backoff
                    }

                    # Try to capture response headers for debugging
                    try {
                        $responseHeaders = $_.Exception.Response.Headers
                    } catch {
                        # Headers not accessible
                    }
                }

                # Extract error content (PowerShell version-agnostic)
                try {
                    # PowerShell 7+ uses ErrorDetails property
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        $errorContent = $_.ErrorDetails.Message
                    }
                    # PowerShell 5.1 uses Response stream
                    elseif ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
                        try {
                            $errorStream = $_.Exception.Response.GetResponseStream()
                            if ($errorStream -and $errorStream.CanRead) {
                                $reader = New-Object System.IO.StreamReader($errorStream)
                                $errorContent = $reader.ReadToEnd()
                                $reader.Close()
                                $errorStream.Close()
                            }
                        } catch {
                            # Stream reading failed, try alternative approach
                            if ($_.Exception.Message) {
                                $errorContent = $_.Exception.Message
                            }
                        }
                    }
                    # Fallback to exception message
                    elseif ($_.Exception.Message) {
                        $errorContent = $_.Exception.Message
                    }
                } catch {
                    # Error content extraction failed
                    $errorContent = $_.Exception.Message
                }

                # Parse error content if available
                if ($null -ne $errorContent) {
                    try {
                        $response.Content = $errorContent | ConvertFrom-Json -ErrorAction Stop
                    } catch {
                        # Not JSON, store as string
                        $response.Content = $errorContent
                    }
                } else {
                    $response.Content = $null
                }

                # Store error information in response object
                # Use 0 for status code if extraction failed (allows callers to check for null/0)
                $response.statusCode = if ($null -ne $statusCode) { $statusCode } else { 0 }

                # Create a more useful status description
                $statusDesc = if ($null -ne $statusCode) {
                    "$($_.Exception.GetType().Name): HTTP $statusCode"
                } else {
                    "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                }
                $response.StatusDescription = $statusDesc
                $response.Headers = $responseHeaders

                # Handle 429 throttling specifically
                if ($statusCode -eq 429) {
                    $throttleRetryCount++

                    # Check if we've exceeded throttle-specific retry limit
                    if ($throttleRetryCount -gt $this.maxThrottleRetries) {
                        $this.requesthistory.Add($response) | Out-Null
                        $ProgressPreference = 'Continue'

                        if ($this.ThrowOnRetryExhaustion) {
                            $errorMessage = "GDAPGraphClient.GraphAPICall: Request $($requestid) failed after $throttleRetryCount throttle retries. Last Status: 429. Last Error: $($response.StatusDescription)"
                            $exception = [GraphAPIException]::new($errorMessage, $response)
                            throw $exception
                        } else {
                            # Return error response instead of throwing
                            return $response
                        }
                    }

                    # Determine wait time: use Retry-After if available, otherwise exponential backoff with jitter
                    if ($retryAfter -gt 0) {
                        $waitTime = $retryAfter
                        Write-Warning "Rate limited (429). Retry-After header indicates wait time: $waitTime seconds (throttle retry $throttleRetryCount/$($this.maxThrottleRetries))..."
                    } else {
                        # Exponential backoff: 2^retryCount * baseDelay + random jitter (0-50% of baseDelay)
                        $exponentialDelay = [Math]::Pow(2, $throttleRetryCount - 1) * $baseDelay
                        $jitter = Get-Random -Minimum 0 -Maximum ([Math]::Max(1, [int]($baseDelay * 0.5)))
                        $waitTime = [Math]::Min([int]($exponentialDelay + $jitter), 300) # Cap at 5 minutes
                        Write-Warning "Rate limited (429). No Retry-After header. Using exponential backoff: waiting $waitTime seconds (throttle retry $throttleRetryCount/$($this.maxThrottleRetries))..."
                    }

                    Start-Sleep -Seconds $waitTime
                    continue  # Retry the request without incrementing general retryCount
                }

                # Handle other HTTP errors (non-429)
                # Retry logic for other errors
                $retryCount++
                if ($retryCount -ge $this.maxretrycount) {
                    $this.requesthistory.Add($response) | Out-Null
                    $ProgressPreference = 'Continue'

                    if ($this.ThrowOnRetryExhaustion) {
                        $errorMessage = "GDAPGraphClient.GraphAPICall: Request $($requestid) failed after $retryCount attempts. Last Status: $($response.statusCode). Last Error: $($response.StatusDescription)"
                        $exception = [GraphAPIException]::new($errorMessage, $response)
                        throw $exception
                    } else {
                        # Return error response instead of throwing
                        return $response
                    }
                }

                Start-Sleep -Seconds $this.retrydelay
            }
        }

        $ProgressPreference = 'Continue'
        $this.requesthistory.Add($response) | Out-Null
        Return $response
    }

    # Method overloads for convenience
    [object]GraphAPICall($Uri, $Method, $additionalHeaders) {
        return $this.GraphAPICall($uri, $method, $additionalHeaders, $null)
    }

    [object]GraphAPICall($Uri, $Method) {
        return $this.GraphAPICall($uri, $method, $null)
    }
}

<#
.SYNOPSIS
    Response object returned by GraphAPICall method

.DESCRIPTION
    Standardized response structure containing:
    - Uri: The endpoint that was called
    - RequestId: Unique GUID for tracking
    - StatusCode: HTTP status code (200, 404, etc.). Value of 0 indicates status code could not be extracted.
    - StatusDescription: Human-readable status or error message
    - Content: Parsed JSON response or raw content (may contain error details for failed requests)
    - Headers: HTTP response headers

.NOTES
    For error handling:
    - Check StatusCode >= 400 for client/server errors
    - Check StatusCode = 0 for unknown/network errors
    - Content may contain error details from the API (typically JSON with 'error' property)
#>
class GraphAPIResponse {
    [string]$Uri
    [string]$RequestId
    [int]$StatusCode
    [string]$StatusDescription
    [object]$Content
    [object]$Headers
}

<#
.SYNOPSIS
    Custom exception class for Graph API errors

.DESCRIPTION
    Extends System.Exception to include the GraphAPIResponse object,
    allowing callers to access detailed error information even when exceptions are thrown.
#>
class GraphAPIException : System.Exception {
    [GraphAPIResponse]$Response

    GraphAPIException([string]$message, [GraphAPIResponse]$response) : base($message) {
        $this.Response = $response
    }

    GraphAPIException([string]$message, [GraphAPIResponse]$response, [System.Exception]$innerException) : base($message, $innerException) {
        $this.Response = $response
    }
}
