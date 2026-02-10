# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

PowerSZhell is a PowerShell library for making authenticated API calls to Microsoft Partner Center, Graph API, and Azure Resource Manager. It provides the `GDAPGraphClient` class for OAuth token management and API calls, plus helper functions for common patterns like pagination and KeyVault integration.

## Architecture

### Core Components

**GDAPGraphClient** (`Classes/GDAPGraphClient.ps1`)
- Main API client class handling OAuth2 token acquisition and authenticated requests
- Three authentication flows:
  - `GetGDAPToken()` - Delegated permissions via refresh token (for GDAP/customer tenant operations)
  - `GetAppToken()` - Application-only permissions via client credentials
  - `GetCSPToken()` - Partner Center API (two-step: Azure AD token → Partner Center token exchange)
- `GraphAPICall()` method handles all HTTP requests with automatic token refresh, retry logic, and 429 throttling with exponential backoff
- Token context is encrypted using machine GUID for secure storage during token refresh
- Predefined API scopes in `$client.APIScopes` hashtable (GraphAPI, MDE, Security, Exchange, Azure, PartnerCenter)

**Supporting Classes**
- `GraphAPIResponse` - Standardized response object with Uri, RequestId, StatusCode, StatusDescription, Content, Headers
- `GraphAPIException` - Custom exception including the GraphAPIResponse for detailed error handling

**CommonHelpers Module** (`Modules/CommonHelpers.psm1`)
- `Get-KeyVaultSecrets` - Azure KeyVault credential retrieval (requires Az.Accounts, Az.KeyVault). Reuses an existing Azure session if already connected to the correct tenant; only calls `Connect-AzAccount` when needed and never disconnects
- `Get-GraphRequestWithPaging` - Microsoft Graph API pagination (`@odata.nextLink`)
- `Get-AzureRequestWithPaging` - Azure ARM pagination (`nextLink`)
- `Get-PartnerCenterRequestWithPaging` - Partner Center pagination (`links.next.uri` + MS-ContinuationToken header)

### Remote Loading

`The2MagicLines.ps1` demonstrates loading the class and module directly from GitHub:
```powershell
. ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Classes/GDAPGraphClient.ps1" -UseBasicParsing).Content))
New-Module -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest "https://raw.githubusercontent.com/ZoeyABT/zCommon/refs/heads/master/Modules/CommonHelpers.psm1" -UseBasicParsing).Content)) -Name CommonHelpers | Import-Module
```

## Key Implementation Details

- Azure ARM API **always** requires delegated tokens (`GetGDAPToken`), not app-only tokens
- Partner Center authentication uses a hardcoded Azure AD tenant ID for the initial token exchange
- Token auto-refresh occurs when <5 minutes remain before expiration
- `ThrowOnRetryExhaustion` property controls error behavior: `$true` throws exceptions, `$false` returns error response objects
- Each API type has different pagination patterns—use the appropriate helper function for the API being called
- `Get-KeyVaultSecrets` checks for an existing `Az` session via `Get-AzContext` before authenticating—callers can `Connect-AzAccount` once per session and all subsequent KeyVault calls will reuse that connection
