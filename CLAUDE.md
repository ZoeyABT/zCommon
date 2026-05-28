# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PowerSZhell is a PowerShell library for making authenticated API calls to Microsoft Partner Center, Graph API, and Azure Resource Manager. It provides the `GDAPGraphClient` class for OAuth token management and API calls, plus helper functions for common patterns like pagination.

## Architecture

### Token Proxy Model

All token acquisition routes through the MWS API token proxy (`https://api.mortgageworkspace.com/API/EntraID/Token`). The proxy handles KeyVault secret retrieval and Microsoft login via managed identity — credentials never leave Azure. The operator authenticates via the MwsTokenBroker WAM module (interactive Windows broker prompt on first use, cached for silent refresh; MSAL is isolated in a private AssemblyLoadContext so it coexists with ExchangeOnlineManagement/MicrosoftTeams), and the proxy uses that bearer token to issue scoped access tokens.

```
Script → MwsTokenBroker (WAM interactive/silent login) → MWS API proxy (get token) → Graph/Partner API
```

### Core Components

**GDAPGraphClient** (`Classes/GDAPGraphClient.ps1`)
- Main API client class handling OAuth2 token acquisition via token proxy and authenticated requests
- Three authentication flows, all routing through `InvokeTokenProxy()`:
  - `GetGDAPToken(tenantid, scope)` - Delegated permissions via `refresh_token` grant (for GDAP/customer tenant operations)
  - `GetAppToken(tenantid, scope)` - Application-only permissions via `client_credentials` grant
  - `GetCSPToken(scope)` - Partner Center API (proxy handles two-step exchange server-side)
- Backward-compatible overloads accept the old (appid, refreshtoken, clientsecret, ...) signatures with deprecation warnings
- `GraphAPICall()` method handles all HTTP requests with automatic token refresh, retry logic, and 429 throttling with exponential backoff
- `ValidateToken()` auto-refreshes via the proxy when <5 minutes remain before expiration
- Predefined API scopes in `$client.APIScopes` hashtable (GraphAPI, MDE, Security, Exchange, Azure, PartnerCenter)
- Key properties: `MsalToken` (operator token), `MWSApiUrl`, `CSPTenantId`

**Supporting Classes**
- `GraphAPIResponse` - Standardized response object with Uri, RequestId, StatusCode, StatusDescription, Content, Headers
- `GraphAPIException` - Custom exception including the GraphAPIResponse for detailed error handling

**CommonHelpers Module** (`Modules/CommonHelpers.psm1`)
- `Get-MWSOperatorToken` - MwsTokenBroker WAM operator authentication (silent with interactive fallback). Returns the token object for `GDAPGraphClient` constructor
- `Get-GraphRequestWithPaging` - Microsoft Graph API pagination (`@odata.nextLink`)
- `Get-AzureRequestWithPaging` - Azure ARM pagination (`nextLink`)
- `Get-PartnerCenterRequestWithPaging` - Partner Center pagination (`links.next.uri` + MS-ContinuationToken header)

### Remote Loading

`The2MagicLines.ps1` demonstrates loading and initializing the library from GitHub:
```powershell
Import-Module MwsTokenBroker
. ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Classes/GDAPGraphClient.ps1" -UseBasicParsing).Content))
New-Module -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Modules/CommonHelpers.psm1" -UseBasicParsing).Content)) -Name CommonHelpers | Import-Module
$MsalToken = Get-MWSOperatorToken
$client = [GDAPGraphClient]::new($MsalToken)
```

## Key Implementation Details

- Azure ARM API **always** requires delegated tokens (`GetGDAPToken`), not app-only tokens
- Partner Center CSP tenant ID (`3376fd25-ade9-423f-99d5-058e6d4214c3`) is stored as `$client.CSPTenantId`; the proxy handles the two-step Partner Center token exchange server-side
- Token auto-refresh occurs when <5 minutes remain before expiration, via the token proxy
- `ThrowOnRetryExhaustion` property controls error behavior: `$true` throws exceptions, `$false` returns error response objects
- Each API type has different pagination patterns—use the appropriate helper function for the API being called
- MwsTokenBroker handles token caching; `Get-MWSOperatorToken` tries silent refresh before falling back to an interactive WAM prompt
- The `InvokeTokenProxy()` hidden method is the single point of contact for all token acquisition
- Old method signatures (with appid, refreshtoken, clientsecret) still work but emit deprecation warnings
