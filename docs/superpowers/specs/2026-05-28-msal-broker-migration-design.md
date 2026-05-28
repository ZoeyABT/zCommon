# zCommon: Migrate operator auth to MwsTokenBroker + remove direct KeyVault

**Date:** 2026-05-28
**Status:** Approved for planning
**Repo:** PowerSZhell (zCommon)

## 1. Objective

Replace the deprecated `MSAL.PS` operator-authentication path in `Get-MWSOperatorToken`
with the new private binary module **`MwsTokenBroker`** (cmdlet `Get-MwsBrokerToken`),
which isolates MSAL in its own `AssemblyLoadContext` so it coexists in-session with
`ExchangeOnlineManagement` and `MicrosoftTeams` (both load `Microsoft.Identity.Client`).

Separately, remove all **direct / client-side** Azure KeyVault access from the repo —
the `Get-KeyVaultSecrets` helper and its `Az.Accounts` / `Az.KeyVault` dependency. We no
longer hit KeyVault directly from scripts; the token proxy handles credential retrieval
server-side.

The public contract of the module is preserved: `Get-MWSOperatorToken` and `New-GDAPClient`
keep their signatures, so no downstream script changes.

## 2. Why this is low-risk

- `GDAPGraphClient` reads only `$this.MsalToken.AccessToken` (see `GDAPGraphClient.ps1:106`).
- `Get-MwsBrokerToken` returns a `PSObject` with exactly `AccessToken` (string) and
  `ExpiresOn` (DateTimeOffset) — a drop-in for the constructor's `[PSCustomObject]$msalToken`.
- The `MsalToken` property name is retained. It still *is* the operator token; renaming
  would break consumers and serve no purpose.

## 3. Known inputs (unchanged from current code)

| Item | Value |
|---|---|
| Operator ClientId | `79d5aeee-e34d-434c-9c4c-a25f18f844b9` |
| Operator TenantId | `3376fd25-ade9-423f-99d5-058e6d4214c3` |
| Scope | `79d5aeee-e34d-434c-9c4c-a25f18f844b9/.default` |
| New module name | `MwsTokenBroker` |
| New cmdlet | `Get-MwsBrokerToken` (params: `-ClientId`, `-TenantId`, `-Scope`, `-ForceInteractive`; all optional, defaulting to the values above) |

The broker cmdlet already defaults `ClientId`/`TenantId`/`Scope` to these values, so
`Get-MWSOperatorToken` does not need to pass them; it only forwards `-ForceInteractive`.

## 4. Module discovery & error handling (decided)

- **Discovery: by name, assume installed.** `Get-MWSOperatorToken` checks
  `Get-Module -ListAvailable -Name MwsTokenBroker`, then `Import-Module MwsTokenBroker`.
  The operator is responsible for installing the private binary module to a `PSModulePath`
  location beforehand (it is **not** on PSGallery and cannot be auto-installed). This matches
  the remote-loading model in `The2MagicLines.ps1`.
- **Missing module: terminating `throw`** with a clear message — that `MwsTokenBroker` is
  required, is a private module (not on PSGallery), and must be installed to a `PSModulePath`
  location. No fallback to MSAL.PS (the point is to retire it).

## 5. Changes by file

### 5.1 `Modules/CommonHelpers.psm1` (functional core)

- **Remove `Initialize-MsalModule`** entirely. The new module is private and cannot be
  auto-installed from PSGallery, so the auto-install helper has no purpose.
- **Rewrite `Get-MWSOperatorToken`:**
  - Guard: if `Get-Module -ListAvailable -Name MwsTokenBroker` is empty → `throw` with
    install guidance. Otherwise `Import-Module MwsTokenBroker -ErrorAction Stop`.
  - Body: `return Get-MwsBrokerToken -ForceInteractive:$ForceInteractive`. The silent-first /
    interactive-fallback logic now lives inside the broker worker, so the old
    try-silent/catch-interactive block is deleted.
  - Update `.PARAMETER` / `.OUTPUTS` / `.NOTES` doc to reference `MwsTokenBroker`.
- **Remove `Get-KeyVaultSecrets`** function in full, and remove `'Get-KeyVaultSecrets'`
  from the `Export-ModuleMember` list.
- Update the module **header `.DESCRIPTION` / `.NOTES`**: drop the "Azure KeyVault credential
  retrieval (legacy)" bullet and the `MSAL.PS` + `Az.Accounts` / `Az.KeyVault` dependency line;
  state the dependency is now `MwsTokenBroker`.
- `New-GDAPClient` and the three paging helpers (`Get-GraphRequestWithPaging`,
  `Get-AzureRequestWithPaging`, `Get-PartnerCenterRequestWithPaging`) are unchanged.

### 5.2 `Classes/GDAPGraphClient.ps1` (doc only)

- Update header doc-comment references (lines ~10, ~15, ~19): `MSAL.PS` /
  `Import-Module MSAL.PS` → `MwsTokenBroker`. No functional code changes.
- The `InvokeTokenProxy` doc (lines ~91-92) describing the proxy's **server-side** KeyVault
  retrieval is accurate and retained (this is not a direct/client-side KeyVault hit).

### 5.3 `The2MagicLines.ps1` (remote-loading example)

- Replace the `Install-Module MSAL.PS` prerequisite comment and `Import-Module MSAL.PS` with
  `Import-Module MwsTokenBroker`, plus a note that it is a private module installed separately
  (not from PSGallery).

### 5.4 `CLAUDE.md` (architecture docs)

- Update the token-proxy flow diagram and the MSAL.PS prose to describe operator auth via the
  `MwsTokenBroker` WAM broker module with ALC isolation (replacing MSAL.PS).
- Remove the `Get-KeyVaultSecrets` bullet from the CommonHelpers section.
- Retain the accurate statement that the **proxy** performs KeyVault secret retrieval
  server-side via managed identity (line ~13) — that is proxy behavior, not a repo dependency.
  *(Open for override during spec review: strip even this mention if a fully KeyVault-free doc
  is preferred.)*

## 6. Out of scope

- No changes to the `MwsTokenBroker` module itself (built and maintained in the `zMSALModule` repo).
- No changes to `GDAPGraphClient` token methods, paging helpers, or the proxy contract.
- No PSGallery publishing of the binary module.

## 7. Verification

- **Load check (automatable):** in a fresh `pwsh -NoProfile`, dot-source the class and import
  the module; assert `Get-Command Get-MWSOperatorToken`, `New-GDAPClient` resolve, and that
  `Get-Command Initialize-MsalModule` / `Get-Command Get-KeyVaultSecrets` do **not** resolve.
- **Missing-module path (automatable):** in a session where `MwsTokenBroker` is not available,
  `Get-MWSOperatorToken` throws the guidance error (no MSAL.PS install attempt).
- **Functional (manual, requires broker installed + interactive sign-in):** `New-GDAPClient`
  returns a client whose `MsalToken.AccessToken` is populated, and a proxy `Get*Token` call
  succeeds.
- **Coexistence (manual):** importing `MwsTokenBroker`, `ExchangeOnlineManagement`, and
  `MicrosoftTeams` in the same session produces no assembly-conflict warning (verified in the
  zMSALModule repo; spot-checked here).
