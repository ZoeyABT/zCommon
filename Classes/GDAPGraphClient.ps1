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
            $this.accessToken = ($cspauthresult.Content | ConvertFrom-Json).access_token
            
            $iat = [datetime]$cspauthResult.headers.date.split(",")[-1]
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
                $this.accessToken = ($cspauthresult.Content | ConvertFrom-Json).access_token
                
                $iat = [datetime]$cspauthResult.headers.date.split(",")[-1]
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
        
        if($tokobj.roles) {
            $this.claims = $tokobj.roles
        }
        elseif($tokobj.scp) {
            $this.claims = $tokobj.scp
        }
    }
    
    <#
    .SYNOPSIS
        Make authenticated API call with automatic retry and token validation
        
    .DESCRIPTION
        Primary method for all API calls. Handles:
        - Automatic token validation/refresh
        - Request retry logic
        - Response tracking in requesthistory
        - JSON serialization of request bodies
        
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
        
    .EXAMPLE
        $response = $client.GraphAPICall("https://graph.microsoft.com/v1.0/users", "GET")
        
    .EXAMPLE
        $body = @{ displayName = "Test User"; userPrincipalName = "test@domain.com" }
        $response = $client.GraphAPICall("https://graph.microsoft.com/v1.0/users", "POST", $null, $body)
    #>
    [object]GraphAPICall($Uri, $Method, $additionalHeaders, $body) {
        # Validate token and set headers
        $this.ValidateToken()
        $Headers = @{Authorization = "Bearer $($this.accesstoken)"}
        
        if($null -ne $additionalHeaders) {
            $AdditionalHeaders.Keys | ForEach-Object {
                $Headers[$_] = $AdditionalHeaders[$_]
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
        while($retryCount -lt $this.maxretrycount) {
            Try {
                if([string]::IsNullOrEmpty($body)) {
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
                # Generic error handling (429 handling commented out for PS 5.x compatibility)
                $response.statusCode = $null
                $response.StatusDescription = $_.Exception.ToString()
                $response.Content = $null
                $response.Headers = $null
            }

            # Retry logic
            $retryCount++
            if ($retryCount -ge $this.maxretrycount) {
                $this.requesthistory.Add($response) | Out-Null
                $ProgressPreference = 'Continue'
                throw "GDAPGraphClient.GraphAPICall: Request $($requestid) failed after $retryCount attempts. Last Status: $($response.statusCode). Last Error: $($response.StatusDescription)"
            }

            Start-Sleep -Seconds $this.retrydelay
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
    - StatusCode: HTTP status code (200, 404, etc.)
    - StatusDescription: Human-readable status or error message
    - Content: Parsed JSON response or raw content
    - Headers: HTTP response headers
#>
class GraphAPIResponse {
    [string]$Uri
    [string]$RequestId
    [int]$StatusCode
    [string]$StatusDescription
    [object]$Content
    [object]$Headers
}

