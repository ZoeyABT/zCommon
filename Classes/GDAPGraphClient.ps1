<#
.SYNOPSIS
    GDAPGraphClient - Universal API client for Microsoft Partner Center, Graph API, and Azure ARM
    
.DESCRIPTION
    A comprehensive PowerShell class for making authenticated API calls to Microsoft Partner Center,
    Graph API, Azure Resource Manager, and other Microsoft APIs. Handles token acquisition,
    automatic refresh, and request retry logic.
    
.NOTES
    Author: ABT Engineering
    Version: 1.0
    Dependencies: None (uses native PowerShell)
    
.EXAMPLE
    # Create client for Partner Center (CSP operations)
    $cspClient = [GDAPGraphClient]::new()
    $cspClient.GetCSPToken($appId, $refreshToken, $clientSecret, $cspClient.APIScopes.PartnerCenter)
    
.EXAMPLE
    # Create client for customer tenant Graph API (delegated)
    $graphClient = [GDAPGraphClient]::new()
    $graphClient.GetGDAPToken($appId, $refreshToken, $clientSecret, $tenantId, $graphClient.APIScopes.GraphAPI)
    
.EXAMPLE
    # Create client for app-only Graph API
    $appClient = [GDAPGraphClient]::new()
    $appClient.GetAppToken($appId, $clientSecret, $tenantId, $appClient.APIScopes.GraphAPI)
#>

class GDAPGraphClient {
    [string]$accesstoken
    [datetime]$expires
    [string]$tokencontext
    [string]$tenantid
    [object]$claims
    [hashtable]$APIScopes
    [System.Collections.ArrayList]$requesthistory
    [int]$maxretrycount = 1
    [int]$retrydelay = 5
    [int]$maxThrottleRetries = 10
    [bool]$ThrowOnRetryExhaustion = $true  # Set to $false to return error response instead of throwing
    
    # Constructor
    GDAPGraphClient() {
        # Initialize request history tracking
        $this.requesthistory = [System.Collections.ArrayList]::New()
        
        # Define available API scopes
        $this.APIScopes = @{
            GraphAPI = 'https://graph.microsoft.com/.default'
            MDE = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
            Security = 'https://api.security.microsoft.com'
            Exchange = 'https://outlook.office365.com/.default'
            Azure = 'https://management.azure.com//user_impersonation'
            PartnerCenter = 'https://api.partnercenter.microsoft.com'
        }
    }

    <#
    .SYNOPSIS
        Acquire delegated token using refresh token (GDAP context)
        
    .DESCRIPTION
        Use this method when you need DELEGATED permissions (user context).
        Required for:
        - Azure Resource Manager API (always requires delegated)
        - Graph API calls requiring delegated permissions
        - Customer tenant operations via GDAP
        
    .PARAMETER appid
        Azure AD Application (Client) ID
        
    .PARAMETER refreshtoken
        Delegated refresh token (long-lived token from user consent)
        
    .PARAMETER clientsecret
        Application client secret
        
    .PARAMETER tenantid
        Target tenant ID to authenticate against
        
    .PARAMETER scope
        API scope (use $this.APIScopes.GraphAPI, $this.APIScopes.Azure, etc.)
    #>
    [void]GetGDAPToken([string]$appid, [string]$refreshtoken, [string]$clientsecret, [string]$tenantid, [string]$scope) {
        $body = @{
            client_id     = $appid
            scope         = $Scope
            refresh_token = $refreshtoken
            client_secret = $clientsecret
            grant_type    = 'refresh_token'
        }
        
        # Store encrypted context for automatic token refresh
        $jsonstr = ([pscustomobject]@{
            client_id     = $appid
            scope         = $Scope
            refresh_token = $refreshtoken
            client_secret = $clientsecret
            grant_type    = 'refresh_token'
        } | ConvertTo-Json)
        
        $enc = [system.Text.Encoding]::UTF8
        $mguid = (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
        $guidbytes = $enc.GetBytes($mguid) 
        $aesKey = $guidbytes[0..31]

        $Secure = ConvertTo-SecureString -String $jsonstr -AsPlainText -Force
        $encstr = ConvertFrom-SecureString -SecureString $Secure -Key $aesKey

        $this.tokencontext = $encstr

        $ProgressPreference = 'SilentlyContinue'

        $retryCount = 0
        while($retryCount -lt $this.maxretrycount) {
            try {
                $authenticationResult = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" `
                    -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop -UseBasicParsing
                
                $this.accesstoken = ($authenticationResult.Content | ConvertFrom-Json).access_token
                $iat = [datetime]$authenticationResult.headers.date.split(",")[-1]
                $this.expires = $iat.AddSeconds(3600)
                $this.tenantid = $tenantid
                $this.DecodeClaims()
                $ProgressPreference = 'Continue'
                break
            }
            catch {
                $retryCount++
                if($retryCount -ge $this.maxretrycount) {
                    $this.tokencontext = $null
                    $ProgressPreference = 'Continue'
                    throw "GDAPGraphClient.GetGDAPToken - Failed to acquire oauth token! Remote server returned $_"
                }
                Start-Sleep -Seconds $this.retrydelay
            }
        }
    }
    
    <#
    .SYNOPSIS
        Acquire application-only token using client credentials
        
    .DESCRIPTION
        Use this method when you need APPLICATION permissions (no user context).
        This is the default for most background automation scenarios.
        Cannot be used for Azure Resource Manager API (requires delegated).
        
    .PARAMETER appid
        Azure AD Application (Client) ID
        
    .PARAMETER clientsecret
        Application client secret
        
    .PARAMETER tenantid
        Target tenant ID to authenticate against
        
    .PARAMETER scope
        API scope (use $this.APIScopes.GraphAPI, $this.APIScopes.MDE, etc.)
    #>
    [void]GetAppToken([string]$appid, [string]$clientsecret, [string]$tenantid, [string]$scope) {
        $body = @{
            client_id     = $appid
            scope         = $Scope
            client_secret = $clientsecret
            grant_type    = "client_credentials"
        }

        # Store encrypted context for automatic token refresh
        $jsonstr = ([pscustomobject]@{
            client_id     = $appid
            scope         = $Scope
            client_secret = $clientsecret
            grant_type    = "client_credentials"
        } | ConvertTo-Json)
        
        $enc = [system.Text.Encoding]::UTF8
        $mguid = (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
        $guidbytes = $enc.GetBytes($mguid) 
        $aesKey = $guidbytes[0..31]

        $Secure = ConvertTo-SecureString -String $jsonstr -AsPlainText -Force
        $encstr = ConvertFrom-SecureString -SecureString $Secure -Key $aesKey

        $this.tokencontext = $encstr
    
        $ProgressPreference = 'SilentlyContinue'
        $retryCount = 0

        while ($retryCount -lt $this.maxretrycount) {
            try {
                $authenticationResult = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" `
                    -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop -UseBasicParsing
                
                $this.accesstoken = ($authenticationResult.Content | ConvertFrom-Json).access_token
                $iat = [datetime]$authenticationResult.headers.date.split(",")[-1]
                $this.expires = $iat.AddSeconds(3600)
                $this.tenantid = $tenantid
                $this.DecodeClaims()
                $ProgressPreference = 'Continue'
                break
            }
            catch {
                $retryCount++
                if ($retryCount -ge $this.maxretrycount) {
                    $this.tokencontext = $null
                    $ProgressPreference = 'Continue'
                    throw "GraphClient.GetAppToken - Failed to acquire oauth token! Remote server returned $_"
                }
                Start-Sleep -Seconds $this.retrydelay
            }
        }
    }
    
    <#
    .SYNOPSIS
        Acquire Partner Center API token (CSP operations)
        
    .DESCRIPTION
        Use this method EXCLUSIVELY for Partner Center API operations.
        This involves a two-step authentication process:
        1. Get Azure AD token using refresh token
        2. Exchange for Partner Center token using jwt_token grant
        
    .PARAMETER appid
        Azure AD Application (Client) ID registered as CSP app
        
    .PARAMETER refreshtoken
        Delegated refresh token with Partner Center consent
        
    .PARAMETER clientsecret
        Application client secret
        
    .PARAMETER scope
        Must be $this.APIScopes.PartnerCenter
    #>
    [void]GetCSPToken([string]$appid, [string]$refreshtoken, [string]$clientsecret, [string]$scope) {
        $body = @{
            client_id     = $appid
            scope         = $Scope
            refresh_token = $refreshtoken
            client_secret = $clientsecret
            grant_type    = 'refresh_token'
        }
        
        # Store encrypted context for automatic token refresh
        $jsonstr = ([pscustomobject]@{
            client_id     = $appid
            scope         = $Scope
            refresh_token = $refreshtoken
            client_secret = $clientsecret
            grant_type    = 'refresh_token'
        } | ConvertTo-Json)

        $enc = [system.Text.Encoding]::UTF8
        $mguid = (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
        $guidbytes = $enc.GetBytes($mguid) 
        $aesKey = $guidbytes[0..31]

        $Secure = ConvertTo-SecureString -String $jsonstr -AsPlainText -Force
        $encstr = ConvertFrom-SecureString -SecureString $Secure -Key $aesKey

        $this.tokencontext = $encstr

        Try {
            # Step 1: Get Azure AD token
            $authenticationResult = Invoke-WebRequest -Method "Post" -Uri "https://login.microsoftonline.com/3376fd25-ade9-423f-99d5-058e6d4214c3/oauth2/token" `
                -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop -UseBasicParsing
            $azadtoken = ($authenticationResult.Content | ConvertFrom-Json).access_token
            
            # Step 2: Exchange for Partner Center token
            $authHeader = @{ 'Authorization' = "Bearer $azadtoken" }
            $body = @{
                grant_type = 'jwt_token'
            }
            $cspauthresult = Invoke-WebRequest -Method "Post" -Uri "https://api.partnercenter.microsoft.com/generatetoken" `
                -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $authHeader -ErrorAction Stop -UseBasicParsing
            $this.accesstoken = ($cspauthresult.Content | ConvertFrom-Json).access_token
            
            $iat = [datetime]$cspauthresult.headers.date.split(",")[-1]
            $this.expires = $iat.AddSeconds(3600)
            $ProgressPreference = 'Continue'
        }
        Catch {
            Throw "GraphClient.GetCSPToken - Failed to get CSP token; Full Error:$_"
        }
    }
    
    <#
    .SYNOPSIS
        Automatically validate and refresh expired tokens
        
    .DESCRIPTION
        Called automatically by GraphAPICall before each request.
        Checks if token expires in <5 minutes and refreshes if needed.
        Uses encrypted tokencontext to re-authenticate without storing secrets.
    #>
    [void]ValidateToken() {
        $timeremaining = $this.expires - (Get-Date)

        # Refresh if less than 5 minutes remaining
        If($timeremaining.TotalSeconds -lt 300) {
            $enc = [system.Text.Encoding]::UTF8
            $mguid = (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
            $guidbytes = $enc.GetBytes($mguid) 
            $aesKey = $guidbytes[0..31]
            
            $secureObject = ConvertTo-SecureString -String $this.tokencontext -Key $aesKey
            $decrypted = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
            $decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decrypted)
            
            $body = @{}
            ($decrypted | ConvertFrom-Json).psobject.properties | ForEach-Object { $body[$_.Name] = $_.Value }
            
            # Partner Center requires special two-step refresh
            if($body.scope -eq 'https://api.partnercenter.microsoft.com') {
                $authenticationResult = Invoke-WebRequest -Method "Post" -Uri "https://login.microsoftonline.com/3376fd25-ade9-423f-99d5-058e6d4214c3/oauth2/token" `
                    -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop -UseBasicParsing
                $azadtoken = ($authenticationResult.Content | ConvertFrom-Json).access_token
                
                $authHeader = @{ 'Authorization' = "Bearer $azadtoken" }
                $body = @{
                    grant_type = 'jwt_token'
                }
                $cspauthresult = Invoke-WebRequest -Method "Post" -Uri "https://api.partnercenter.microsoft.com/generatetoken" `
                    -ContentType "application/x-www-form-urlencoded" -Body $body -Headers $authHeader -ErrorAction Stop -UseBasicParsing
                $this.accesstoken = ($cspauthresult.Content | ConvertFrom-Json).access_token
                
                $iat = [datetime]$cspauthresult.headers.date.split(",")[-1]
                $this.expires = $iat.AddSeconds(3600)
                $ProgressPreference = 'Continue'
            }
            else {
                # Standard token refresh for Graph API, Azure, etc.
                $authenticationResult = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$($this.tenantid)/oauth2/v2.0/token" `
                    -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop -UseBasicParsing
                
                $this.accesstoken = ($authenticationResult.Content | ConvertFrom-Json).access_token
                $iat = [datetime]$authenticationResult.headers.date.split(",")[-1]
                $this.expires = $iat.AddSeconds(3600)
                $ProgressPreference = 'Continue'
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
                    # Ensure body is JSON string
                    $requestBody = if ($body -is [string]) { $body } else { $body | ConvertTo-Json -Depth 5 }
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

