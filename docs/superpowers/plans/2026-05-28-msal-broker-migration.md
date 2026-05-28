# MSAL.PS → MwsTokenBroker Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the deprecated MSAL.PS operator-auth path in zCommon with the private `MwsTokenBroker` WAM module, and remove all direct/client-side KeyVault access.

**Architecture:** `Get-MWSOperatorToken` becomes a thin wrapper over `Get-MwsBrokerToken` (which returns a `PSObject` with `AccessToken`/`ExpiresOn`, a drop-in for `GDAPGraphClient`'s `[PSCustomObject]$msalToken` constructor). The `Initialize-MsalModule` auto-installer and the `Get-KeyVaultSecrets` helper are deleted. All other files change only in doc comments / prose.

**Tech Stack:** PowerShell 7.x, the private binary module `MwsTokenBroker` (cmdlet `Get-MwsBrokerToken`).

**Spec:** `docs/superpowers/specs/2026-05-28-msal-broker-migration-design.md`

---

## File Structure

| File | Change |
|---|---|
| `tests/Migration.Tests.ps1` | **Create** — automatable surface + missing-module-guard checks (no real token acquired) |
| `Modules/CommonHelpers.psm1` | **Modify** — remove `Initialize-MsalModule` & `Get-KeyVaultSecrets`; rewrite `Get-MWSOperatorToken`; update header + export list |
| `Classes/GDAPGraphClient.ps1` | **Modify** — 3 header doc-comment lines (MSAL.PS → MwsTokenBroker) |
| `The2MagicLines.ps1` | **Modify** — prerequisite comment + `Import-Module` line |
| `CLAUDE.md` | **Modify** — auth prose, flow diagram, component bullets (keep proxy's server-side KeyVault mention) |

Branch (already created): `migrate-msal-broker`.

---

### Task 1: Automatable migration test

**Files:**
- Create: `tests/Migration.Tests.ps1`

- [ ] **Step 1: Write the test script**

Create `tests/Migration.Tests.ps1` with exactly this content:

```powershell
#Requires -Version 7.4
# Automatable verification for the MSAL.PS -> MwsTokenBroker migration.
# Does NOT acquire a real token (never calls the broker); only checks the
# exported command surface and the missing-module guard.

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\Modules\CommonHelpers.psm1'

function Assert-True($condition, $message) {
    if (-not $condition) { throw "FAIL: $message" }
    Write-Host "PASS: $message" -ForegroundColor Green
}

# Load the module in this session
Import-Module $modulePath -Force

# 1. Deprecated helpers are gone
Assert-True ($null -eq (Get-Command Initialize-MsalModule -ErrorAction SilentlyContinue)) `
    'Initialize-MsalModule is removed'
Assert-True ($null -eq (Get-Command Get-KeyVaultSecrets -ErrorAction SilentlyContinue)) `
    'Get-KeyVaultSecrets is removed'

# 2. Public surface is intact
Assert-True ($null -ne (Get-Command Get-MWSOperatorToken -ErrorAction SilentlyContinue)) `
    'Get-MWSOperatorToken is exported'
Assert-True ($null -ne (Get-Command New-GDAPClient -ErrorAction SilentlyContinue)) `
    'New-GDAPClient is exported'

# 3. Missing-module guard throws (isolated child: PSModulePath has only $PSHOME\Modules,
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
```

- [ ] **Step 2: Run the test to verify it FAILS**

Run: `pwsh -NoProfile -File tests/Migration.Tests.ps1`
Expected: FAIL on the first assertion — `FAIL: Initialize-MsalModule is removed` (the function still exists in the current module).

- [ ] **Step 3: Commit the test**

```bash
git add tests/Migration.Tests.ps1
git commit -m "test: add migration surface checks (failing)"
```

---

### Task 2: Migrate `CommonHelpers.psm1`

**Files:**
- Modify: `Modules/CommonHelpers.psm1`
- Test: `tests/Migration.Tests.ps1`

- [ ] **Step 1: Replace the module header doc block**

Replace lines 1–16 (the opening `<# ... #>` comment) with:

```powershell
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
```

- [ ] **Step 2: Remove `Initialize-MsalModule` entirely**

Delete the whole block from its doc comment `<# ... Ensure the MSAL.PS module ... #>` through the end of the `function Initialize-MsalModule { ... }` body (current lines 18–49), including the blank line after it.

- [ ] **Step 3: Replace the `Get-MWSOperatorToken` doc block and function body**

Replace the entire `Get-MWSOperatorToken` doc comment + function (current lines 51–108) with:

```powershell
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
```

- [ ] **Step 4: Remove `Get-KeyVaultSecrets` entirely**

Delete the whole block from its doc comment `<# ... Retrieve secrets from Azure KeyVault ... #>` through the end of the `function Get-KeyVaultSecrets { ... }` body (current lines ~110–195), including the surrounding blank lines so no double gap remains before `Get-GraphRequestWithPaging`.

- [ ] **Step 5: Remove `Get-KeyVaultSecrets` from the export list**

In the `Export-ModuleMember -Function @( ... )` block, delete the `'Get-KeyVaultSecrets',` line. The final list must be exactly:

```powershell
Export-ModuleMember -Function @(
    'New-GDAPClient',
    'Get-MWSOperatorToken',
    'Get-GraphRequestWithPaging',
    'Get-AzureRequestWithPaging',
    'Get-PartnerCenterRequestWithPaging'
)
```

- [ ] **Step 6: Run the test to verify it PASSES**

Run: `pwsh -NoProfile -File tests/Migration.Tests.ps1`
Expected: all `PASS:` lines, ending with `All migration checks passed.` Exit code 0.

- [ ] **Step 7: Commit**

```bash
git add Modules/CommonHelpers.psm1
git commit -m "feat: migrate Get-MWSOperatorToken to MwsTokenBroker; remove KeyVault helper"
```

---

### Task 3: Update `GDAPGraphClient.ps1` doc comments

**Files:**
- Modify: `Classes/GDAPGraphClient.ps1`

These are documentation-only edits; no functional code changes. `MsalToken` (property name) and the `InvokeTokenProxy` proxy-KeyVault doc are intentionally left as-is.

- [ ] **Step 1: Update the three header references**

- Line 10: `    Requires MSAL.PS module for operator authentication.` → `    Requires the MwsTokenBroker module for operator authentication.`
- Line 15: `    Dependencies: MSAL.PS module` → `    Dependencies: MwsTokenBroker module`
- Line 19: `    Import-Module MSAL.PS` → `    Import-Module MwsTokenBroker`

- [ ] **Step 2: Verify no functional MSAL.PS references remain**

Run: `pwsh -NoProfile -Command "Select-String -Path Classes/GDAPGraphClient.ps1 -Pattern 'MSAL\.PS','Get-MsalToken'"`
Expected: no output (empty). The remaining `MsalToken` property and the line-91 proxy KeyVault doc are expected and not matched by this pattern.

- [ ] **Step 3: Confirm the class still parses**

Run: `pwsh -NoProfile -Command ". ./Classes/GDAPGraphClient.ps1; [GDAPGraphClient]::new() | Out-Null; 'OK'"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add Classes/GDAPGraphClient.ps1
git commit -m "docs: reference MwsTokenBroker in GDAPGraphClient header"
```

---

### Task 4: Update `The2MagicLines.ps1`

**Files:**
- Modify: `The2MagicLines.ps1`

- [ ] **Step 1: Replace the prerequisite comment and import (lines 1–2)**

Replace:

```powershell
# Prerequisites: Install-Module MSAL.PS -Scope CurrentUser
Import-Module MSAL.PS
```

with:

```powershell
# Prerequisites: MwsTokenBroker module installed to a PSModulePath location
# (private binary module, not on PSGallery — build it from the zMSALModule repo)
Import-Module MwsTokenBroker
```

- [ ] **Step 2: Verify**

Run: `pwsh -NoProfile -Command "Select-String -Path The2MagicLines.ps1 -Pattern 'MSAL\.PS'"`
Expected: no output (empty).

- [ ] **Step 3: Commit**

```bash
git add The2MagicLines.ps1
git commit -m "docs: use MwsTokenBroker in remote-loading example"
```

---

### Task 5: Update `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

Keep the statement that the **proxy** performs KeyVault secret retrieval server-side (decided during spec review). Only client-side MSAL.PS / `Get-KeyVaultSecrets` references change.

- [ ] **Step 1: Update the Token Proxy Model paragraph (line 13)**

Replace the sentence:
`The operator authenticates via MSAL.PS (interactive browser login, cached for silent refresh), and the proxy uses that bearer token to issue scoped access tokens.`
with:
`The operator authenticates via the MwsTokenBroker WAM module (interactive Windows broker prompt on first use, cached for silent refresh; MSAL is isolated in a private AssemblyLoadContext so it coexists with ExchangeOnlineManagement/MicrosoftTeams), and the proxy uses that bearer token to issue scoped access tokens.`

The first sentence about the proxy handling KeyVault secret retrieval is unchanged.

- [ ] **Step 2: Update the flow diagram (line 16)**

Replace:
`Script → MSAL.PS (interactive/silent login) → MWS API proxy (get token) → Graph/Partner API`
with:
`Script → MwsTokenBroker (WAM interactive/silent login) → MWS API proxy (get token) → Graph/Partner API`

- [ ] **Step 3: Update the `Get-MWSOperatorToken` component bullet (line 38)**

Replace:
`- `Get-MWSOperatorToken` - MSAL.PS operator authentication (silent with interactive fallback). Returns the token object for `GDAPGraphClient` constructor`
with:
`- `Get-MWSOperatorToken` - MwsTokenBroker WAM operator authentication (silent with interactive fallback). Returns the token object for `GDAPGraphClient` constructor`

- [ ] **Step 4: Remove the `Get-KeyVaultSecrets` component bullet (line 39)**

Delete this entire line:
`- `Get-KeyVaultSecrets` - Azure KeyVault credential retrieval (legacy, still available for non-auth use cases)`

- [ ] **Step 5: Update the Remote Loading example (line 48)**

Replace:
`Import-Module MSAL.PS`
with:
`Import-Module MwsTokenBroker`

- [ ] **Step 6: Update the token-caching implementation note (line 62)**

Replace:
`- MSAL.PS handles token caching; `Get-MWSOperatorToken` tries silent refresh before falling back to interactive login`
with:
`- MwsTokenBroker handles token caching; `Get-MWSOperatorToken` tries silent refresh before falling back to an interactive WAM prompt`

- [ ] **Step 7: Verify only the intended KeyVault/MSAL references remain**

Run: `pwsh -NoProfile -Command "Select-String -Path CLAUDE.md -Pattern 'MSAL\.PS','Get-KeyVaultSecrets'"`
Expected: no output (empty).

Run: `pwsh -NoProfile -Command "Select-String -Path CLAUDE.md -Pattern 'KeyVault'"`
Expected: exactly one match — the line-13 sentence about the proxy handling KeyVault secret retrieval server-side.

- [ ] **Step 8: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for MwsTokenBroker auth; drop client-side KeyVault"
```

---

### Task 6: Final repo-wide verification

**Files:** none (verification only)

- [ ] **Step 1: Re-run the migration test**

Run: `pwsh -NoProfile -File tests/Migration.Tests.ps1`
Expected: all `PASS:` lines + `All migration checks passed.`

- [ ] **Step 2: Confirm no stray MSAL.PS / dead-helper references in code or docs**

Run: `pwsh -NoProfile -Command "Get-ChildItem -Recurse -Include *.ps1,*.psm1,*.md -File | Where-Object { $_.FullName -notmatch 'docs\\superpowers' } | Select-String -Pattern 'MSAL\.PS','Initialize-MsalModule','Get-KeyVaultSecrets'"`
Expected: no output (empty). (Spec/plan docs under `docs/superpowers` are excluded — they intentionally mention the old names as history.)

- [ ] **Step 3: Manual functional check (requires MwsTokenBroker installed; interactive)**

This step cannot be automated (it triggers a real WAM sign-in) — run it by hand on a machine with the module installed:

```powershell
. ./Classes/GDAPGraphClient.ps1
Import-Module ./Modules/CommonHelpers.psm1 -Force
$client = New-GDAPClient
$client.MsalToken.AccessToken.Length -gt 0   # expect: True
$client.GetCSPToken($client.APIScopes.PartnerCenter)  # expect: no error, token set
```

Document the result in the PR description; do not block the automated steps on it.

---

## Notes for the implementer

- Line numbers above are from the pre-change snapshot; if an edit has shifted them, match on the quoted text instead.
- Do not rename the `MsalToken` property — downstream scripts and `GDAPGraphClient` depend on it.
- `Get-MwsBrokerToken` already defaults `ClientId`/`TenantId`/`Scope` to the operator values, so `Get-MWSOperatorToken` forwards only `-ForceInteractive`.
- The work happens on branch `migrate-msal-broker` (already created and holding the spec commit).
