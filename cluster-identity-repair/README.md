# Repair-AzureLocalClusterIdentity

A PowerShell script that replaces the expired or lost system-assigned managed identity of an Azure Local cluster resource (`Microsoft.AzureStackHCI/clusters`), repairs the cluster registration, and checks that the cluster syncs with Azure again. It adds read-only pre-flight checks, confirmation prompts, resume stages, and an evidence folder.

## Purpose

An Azure Local cluster uses a system-assigned managed identity on the `Microsoft.AzureStackHCI/clusters` resource to communicate with the resource provider in Azure and authenticate the cluster with Azure; the identity is also used by the Azure Monitor Agent and Azure Site Recovery. If that managed identity's signing certificate expires without automatic renewal, `Register-AzStackHCI -RepairRegistration` can fail with `MsiProvisionFailed` (`HTTP 404 NotFound` on `msiDetails`).

Microsoft Support provided a remediation for this issue (it is not published on Microsoft Learn). That remediation resets the cluster resource's managed identity (`identity.type = None`, then `identity.type = SystemAssigned`) so Azure provisions a fresh service principal, and then runs `Register-AzStackHCI -RepairRegistration` on a cluster node to pull down the new credential.

This script wraps that remediation with read-only pre-flight checks, resource lock and RBAC role assignment inspection, confirmation prompts (`-WhatIf` and `-Confirm`), step-by-step verification, a stage-based resume mechanism, and an audit evidence folder.

## When to use

Microsoft recommends that you open a support request and confirm that your cluster has this issue before you reset its identity. Use this script only when all three symptoms below are present:

1. Running `Register-AzStackHCI -RepairRegistration` locally on a cluster node fails with `MsiProvisionFailed` (and the HciSvc debug log (event channel `Microsoft-AzureStack-HCI/Debug`) shows `HTTP 404 NotFound` on the `msiDetails` endpoint).
2. The HciSvc debug log (event channel `Microsoft-AzureStack-HCI/Debug`), or Microsoft Entra managed identity sign-in logs if available, shows token acquisition failures with `AADSTS700027` (certificate used to sign the client assertion is expired) for the cluster managed identity. This channel is disabled by default. Enable it to capture these events.
3. `Get-AzureStackHCI` on the cluster node reports `RegistrationStatus: Registered` and `ConnectionStatus: NotRecently`, and in Azure `properties.connectivityStatus` shows `NotConnectedRecently` or `Disconnected` for an extended period.

**Applies to:** Clusters for which Microsoft Support has confirmed this issue and prescribed this remediation (prescribed by Microsoft Support for an Azure Local system with OS version 24H2 (build 26100), using `Microsoft.AzureStackHCI/clusters` API version `2024-02-15-preview`). **Validation status:** Validated offline with the mocked Pester acceptance test suite on Windows PowerShell 5.1 and PowerShell 7; not yet run on a live cluster.

## Prerequisites

- **Execution host:** Run the script on a cluster node. It checks that the local machine is a cluster member and runs `Get-AzureStackHCI` and `Register-AzStackHCI` locally, without `-ComputerName`.
- **Elevation:** Windows PowerShell 5.1 running as **Administrator** (`local administrator` on the cluster nodes, such as the deployment user account). The script also parses and passes its tests in PowerShell 7, but PowerShell 7 has not been validated on a cluster node.
- **PowerShell modules on the node:**
  - `Az.Accounts` `>= 2.11.2` (`Invoke-AzRestMethod` with `-Uri`, `Connect-AzAccount`, `Get-AzContext`)
  - `Az.Resources` `>= 6.2.0` (required by `Register-AzStackHCI`)
  - `Az.StackHCI` (`Register-AzStackHCI`, current release recommended)
  - `AzureStackHCI` (`Get-AzureStackHCI`, `Sync-AzureStackHCI`)
  - `FailoverClusters` (`Get-ClusterNode`)
- **Azure permissions:** one Azure account that signs in with device code. It needs:
  - `Microsoft.AzureStackHCI/clusters/read` and `/write` on the cluster resource (`GET` and `PATCH`), granted at resource-group scope or higher. ARM's async-operation status URL is not scoped to the resource, so resource-only rights can start the `PATCH` but cannot track it.
  - `Microsoft.Authorization/locks/read` on the resource.
  - `Microsoft.Authorization/roleAssignments/read` at **subscription** scope.
  - The permissions that `Register-AzStackHCI` needs to repair the registration.

  The built-in role **Azure Stack HCI Administrator** or **Owner**, assigned at subscription scope, covers all of these. Microsoft Entra directory roles are not needed for the identity reset.

## Risks

- **Deletion of old managed identity and orphaned RBAC role assignments:** Setting `identity.type` to `None` permanently deletes the existing system-assigned managed identity service principal in Microsoft Entra ID. Deleting a managed identity does **not** automatically delete its Azure RBAC role assignments: those role assignments remain as **orphaned** entries (`Identity not found`), and the new service principal has none of those permissions. You must recreate any required role assignments on the new `principalId` and clean up the orphaned role assignments manually. This script's own calls never modify RBAC.
  - When `-ResumeFrom Start` is used, pre-flight step 8 lists the old principal's role assignments at, above, and below the subscription scope (management groups included), saves them to `role-assignments-before.json` in the run evidence folder, and stops with exit code `1` if any exist unless `-AcceptRoleAssignmentLoss` is specified. It does not check other subscriptions. It also does not check grants that are not Azure RBAC, such as Key Vault access policies or Microsoft Graph app roles. Check these by hand if the cluster identity was given access outside this subscription.
- **Changes made by `Register-AzStackHCI -RepairRegistration` itself:** `Register-AzStackHCI -RepairRegistration` deletes the local registration certificates on every cluster node and the remote certificates in the Microsoft Entra application in the cloud, generates replacement certificates for both (per `Az.StackHCI` cmdlet help), and, outside cloud deployments, may assign the Azure Connected Machine Resource Manager role to the HCI resource provider service principal (`Az.StackHCI` module source). While this script itself sends no RBAC write, the underlying `Register-AzStackHCI` cmdlet may perform that role assignment. If any cluster node is not `Up` during pre-flight, the script logs a warning because certificate replacement touches every node.
- **User-assigned managed identities:** If the cluster resource also has user-assigned identities (`identity.type` contains `UserAssigned`), setting `identity.type` to `None` would remove them too. Pre-flight stops with exit code `1` and makes no changes when user-assigned identities are present.
- **Brief window without a cluster identity:** One confirmation prompt covers both identity `PATCH` steps (`None` and `SystemAssigned`) so declining a prompt cannot split them. However, between step 1 (`identity.type = None`) and step 2 (`identity.type = SystemAssigned`), the cluster resource has no managed identity. If step 2 fails, times out, or is interrupted, the script exits with code `4` and prints the exact `-ResumeFrom AssignIdentity` command.
- **ReadOnly locks:** A `ReadOnly` resource lock blocks `PATCH` operations and causes pre-flight to stop with exit code `1`. A `CanNotDelete` lock does not block `PATCH` and is allowed.

## Configuration (`config.example.json`)

Copy `config.example.json` to a separate, access-restricted location outside this folder (for example, `C:\ClusterRepair\cluster-identity-repair.json`), fill in your cluster's values, and pass the path to `-ConfigPath`. Unknown keys, invalid GUIDs, or invalid ARM resource/region names cause configuration validation to fail with exit code `7` before any Azure call is made.

| Field | Required | Default | Description |
|---|---|---|---|
| `tenantId` | Yes | - | Microsoft Entra tenant GUID (`<tenant-guid>`). |
| `subscriptionId` | Yes | - | Azure subscription GUID (`<subscription-guid>`) containing the cluster resource. |
| `resourceGroupName` | Yes | - | Resource group name containing the `Microsoft.AzureStackHCI/clusters` resource (1-90 characters of letters, digits, `-`, `_`, `.`, `(`, `)`, not ending in `.`). |
| `clusterName` | Yes | - | Name of the `Microsoft.AzureStackHCI/clusters` resource in Azure (letters, digits, `-`, `_`, `.` only). |
| `region` | Yes | - | Azure region of the cluster resource (letters and digits only, such as `westeurope` or `eastus`); verified case-insensitively against the ARM resource `location`. |
| `apiVersion` | No | `2024-02-15-preview` | Preview ARM API version used to `GET` and `PATCH` the `Microsoft.AzureStackHCI/clusters` resource, chosen because Microsoft's remediation was tested with it. |
| `expectedCloudId` | No | `null` | Optional GUID (`<cloud-id-guid>`). When set, pre-flight verifies that `properties.cloudId` on the ARM cluster resource matches this value. |
| `logDirectory` | No | `C:\Temp\ClusterIdentityRepair` | Base directory where the unique UTC timestamped evidence folder `<logDirectory>\<yyyyMMddTHHmmssZ>-<random>\` is created. |
| `pollIntervalSeconds` | No | `10` | Interval in seconds between polling attempts for ARM operations and `Get-AzureStackHCI`. |
| `identityTimeoutSeconds` | No | `300` | Maximum time in seconds to wait for ARM async operations and identity state changes (`None` or new `SystemAssigned` `principalId`). |
| `propagationWaitSeconds` | No | `60` | Wait time in seconds after a new `principalId` appears before running `Register-AzStackHCI -RepairRegistration` (allows Microsoft Entra replication). |
| `syncWatchMinutes` | No | `10` | Maximum time in minutes after `Sync-AzureStackHCI` to poll `Get-AzureStackHCI` for `ConnectionStatus = Connected` and a newer `LastConnected` timestamp. |

## Usage

### 1. Dry run (`-WhatIf`)

Always run the dry run first. It runs all read-only pre-flight checks (including device-code sign-in if needed), exports current state and role assignments, and previews the write actions without changing anything:

```powershell
.\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -WhatIf
```

If the old identity has role assignments, the dry run exports them and stops with exit code `1`. Review `role-assignments-before.json`, then run `-WhatIf -AcceptRoleAssignmentLoss` to see the rest of the plan.

### 2. Interactive run (prompts before each write phase)

By default, `ConfirmImpact` is `High`, so PowerShell prompts for confirmation once for the identity replacement (`None` then `SystemAssigned`), once before `Register-AzStackHCI -RepairRegistration`, and once before `Sync-AzureStackHCI`:

```powershell
.\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json
```

### 3. Non-interactive confirmation

Expect up to two device-code sign-ins (`pre-flight` if no matching Azure context is active, and `Register-AzStackHCI`). `-Confirm:$false` skips the `ShouldProcess` confirmation prompts, but the run still needs a person at the console for device-code authentication:

```powershell
.\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -Confirm:$false
```

### 4. Accepting role assignment loss

If the old managed identity has RBAC role assignments in the subscription and you have reviewed `role-assignments-before.json` and planned their recreation on the new principal:

```powershell
.\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -AcceptRoleAssignmentLoss
```

## Exit codes

When run as a script, `Repair-AzureLocalClusterIdentity.ps1` exits with one of the following codes (when dot-sourced, `Invoke-ClusterIdentityRepair` returns the code as an `[int]`):

| Code | Meaning |
|---|---|
| `0` | Success (or `-WhatIf` completed with no write). |
| `1` | Pre-flight check failed (or the cluster identity changed between pre-flight and confirmation); nothing was changed. |
| `2` | You declined a confirmation prompt, and the step you declined did not run. Steps you confirmed before it stay done. If you declined at the registration prompt, the identity has already been replaced; run `-ResumeFrom RepairRegistration`. If you declined `-ResumeFrom AssignIdentity` when the cluster had no identity, run `-ResumeFrom AssignIdentity` as soon as possible. The script prints the exact resume command for each declined prompt. |
| `3` | Removing the identity failed or its result is unknown. The script reads the resource once and logs the identity it finds. Compare that `principalId` with `oldPrincipalId` in `summary.json` (also recorded at `clusterResource.identity.principalId` in `before.json`): same principal -> run again without `-ResumeFrom`; no identity -> `-ResumeFrom AssignIdentity`; a different principal -> `-ResumeFrom RepairRegistration`. |
| `4` | Assigning the new identity (`identity.type = SystemAssigned`) failed, threw an error, was interrupted after removal, or no new `principalId` appeared within `identityTimeoutSeconds`; the cluster may currently have **no** identity. |
| `5` | `Register-AzStackHCI -RepairRegistration` failed, threw an error, was interrupted, or its output did not contain a single `Result : Success` line. |
| `6` | Repair steps completed, but `Sync-AzureStackHCI` threw an error, was interrupted, or the cluster did not report `ConnectionStatus = Connected` with a newer `LastConnected` timestamp within `syncWatchMinutes`. |
| `7` | Configuration file missing or invalid (checked before any Azure call or transcript start). |

## Resume

If a run stops after completing an earlier write step, use `-ResumeFrom` so completed steps are not repeated. If `summary.json` is missing because the PowerShell window was closed mid-run, do not assume nothing changed; inspect the cluster resource in Azure first.

- **After exit code `4` (old identity removed, assigning new identity failed or timed out):**

  ```powershell
  .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -ResumeFrom AssignIdentity
  ```

  If the resource already has a `SystemAssigned` identity (for example, a previous run's assignment completed late), `-ResumeFrom AssignIdentity` first refuses (exit `1`) if the present `principalId` matches the `oldPrincipalId` of any earlier run's `summary.json` in `logDirectory` (`<yyyyMMddTHHmmssZ>-<random>` run folders), and then checks that its `principalId` differs from the replaced principal recorded in the newest strip-succeeded `summary.json` (or supplied via `-PreviousPrincipalId <guid>`). If the present principal equals an old principal, the script exits `1` and tells you to run again without `-ResumeFrom`. If it differs, the script uses it as the new identity without sending a `PATCH` and proceeds to registration repair.

- **After exit code `5` (new `SystemAssigned` identity is already provisioned in ARM, `Register-AzStackHCI -RepairRegistration` failed):**

  ```powershell
  .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -ResumeFrom RepairRegistration
  ```

- **After exit code `6` (registration repair succeeded, waiting for `Sync-AzureStackHCI` / `LastConnected` failed or timed out):**

  ```powershell
  .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -ResumeFrom Verify
  ```

Pre-flight checks always run on resume to confirm modules, node state, Azure context, cluster resource, and locks before executing the remaining steps. `-ResumeFrom RepairRegistration` and `-ResumeFrom Verify` require a `SystemAssigned` identity with a `principalId` on the cluster resource (otherwise they exit `1` and point to `-ResumeFrom AssignIdentity`). On any resume stage, pre-flight skips the role-assignment loss gate because the identity on the resource is the new one.

### If Register still fails

If `Register-AzStackHCI -RepairRegistration` fails after the cluster identity has already been replaced (exit code `5`), resume **once** with `-ResumeFrom RepairRegistration`. If registration repair fails a second time, **stop**, keep the evidence folder, and contact Microsoft Support. Never re-run the script without `-ResumeFrom` (`-ResumeFrom Start`) after an identity replacement has already succeeded: a `Start` run deletes the newly provisioned identity on the resource and triggers another certificate cycle across the nodes. To prevent accidental repeat resets, pre-flight with `-ResumeFrom Start` checks whether the current `principalId` on the cluster matches `newPrincipalId` in any earlier `summary.json` under `logDirectory` and exits `1` before any write unless you explicitly pass `-AllowRepeatReplacement` (use `-AllowRepeatReplacement` only if Microsoft Support asks for another identity reset).

## Evidence folder

After configuration validation and the administrator check succeed, each execution creates `<logDirectory>\<yyyyMMddTHHmmssZ>-<random>\` (on Windows, both `<logDirectory>` when created by the script and the run folder are restricted to `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM` with inheritance disabled when possible; if ACL restriction fails, a warning is logged and execution continues) containing:

- `transcript.txt`: PowerShell session transcript of operator messages and command output (always stopped on exit; if `Start-Transcript` cannot start, the script logs a warning and sets `transcript: false` in `summary.json`).
- `before.json`: Pre-flight snapshot of the ARM cluster resource JSON and local `Get-AzureStackHCI` properties.
- `role-assignments-before.json`: Subscription role assignments for the old `principalId` prior to identity removal (written when `-ResumeFrom Start` is used).
- `after.json`: Best-effort post-sync snapshot of the ARM cluster resource JSON and local `Get-AzureStackHCI` properties (written when the verification step is reached and the Azure session is still connected; skipped without a new sign-in prompt if `Register-AzStackHCI` disconnected the session).
- `summary.json`: Written on every exit path after the evidence folder is created (`startedUtc`, `endedUtc`, `exitCode`, `interrupted`, `transcript`, `resumeFrom`, `oldPrincipalId`, `newPrincipalId`, and `steps` with `name`, `status`, `utc`). If the evidence folder itself cannot be created, PowerShell stops before `summary.json` can be written.

No access tokens, passwords, or credentials are written to any evidence file. Do not paste secrets into the console while the transcript is active. The evidence contains tenant, subscription, resource, and object IDs, node inventory, and an RBAC map; keep the folder access-restricted and review it before sharing it outside your organization or attaching it to a support case.

## Running tests

From the folder that contains this README, run the offline Pester 5 acceptance test suite (which mocks all Azure and cluster cmdlets):

```powershell
pwsh -NoProfile -Command "Invoke-Pester -Path ./tests -Output Detailed -CI"
```

## References

- [Managed identity best practice recommendations - Maintenance (orphaned role assignments)](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations#maintenance)
- [Role Assignments - List For Subscription REST API (`2022-04-01`)](https://learn.microsoft.com/rest/api/authorization/role-assignments/list-for-subscription)
- [Track asynchronous Azure operations (permissions and polling protocols)](https://learn.microsoft.com/azure/azure-resource-manager/management/async-operations)
- [Azure built-in roles for Hybrid + multicloud - Azure Stack HCI Administrator](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/hybrid-multicloud#azure-stack-hci-administrator)
- [Enhanced management of Azure Local with managed identity](https://learn.microsoft.com/azure/azure-local/manage/azure-enhanced-management-managed-identity)
- [Microsoft.AzureStackHCI/clusters template reference (`2024-02-15-preview`)](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-02-15-preview/clusters)
- [`Register-AzStackHCI` reference (`Az.StackHCI`)](https://learn.microsoft.com/powershell/module/az.stackhci/register-azstackhci)

## Disclaimer

This script is provided **as-is** without warranty of any kind. Microsoft recommends confirming with Microsoft Support that your cluster matches this specific expired/lost managed identity issue before resetting the cluster identity. Deleting a system-assigned managed identity deletes the old service principal in Microsoft Entra ID, but does **not** automatically delete its Azure RBAC role assignments: they remain as orphaned (`Identity not found`) assignments, and the new principal has none of them. Review `role-assignments-before.json`, recreate any required role assignments on the `newPrincipalId` recorded in `summary.json`, and clean up the orphaned role assignments manually.
