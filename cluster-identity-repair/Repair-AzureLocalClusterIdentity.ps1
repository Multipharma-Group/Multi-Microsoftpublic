<#
.SYNOPSIS
    Replaces a lost or expired system-assigned managed identity on an Azure Local cluster resource and repairs registration.

.DESCRIPTION
    Performs a guarded, step-by-step repair when an Azure Local cluster's system-assigned managed identity
    certificate has expired or been lost (for example, when Register-AzStackHCI -RepairRegistration fails
    with MsiProvisionFailed and the HciSvc debug log (event channel Microsoft-AzureStack-HCI/Debug) reports
    AADSTS700027):

      1. Validates configuration and runs read-only pre-flight checks (required modules and versions,
         elevation, cluster node membership, local registration state, Azure context, ARM cluster resource,
         user-assigned identity absence, resource locks, and existing RBAC role assignments on the old
         principal when stripping).
      2. After a single confirmation prompt covering the identity replacement, re-reads the cluster resource
         to confirm its identity has not changed since pre-flight, sends an ARM PATCH to set identity.type
         to None, and waits until the stale identity is removed.
      3. Sends an ARM PATCH to set identity.type to SystemAssigned, waits until a new principalId is
         provisioned, and waits for Microsoft Entra ID replication.
      4. Runs Register-AzStackHCI -RepairRegistration on the local cluster node to fetch and store the
         new managed identity credential.
      5. Runs Sync-AzureStackHCI and polls Get-AzureStackHCI until ConnectionStatus is Connected with a
         newer LastConnected timestamp.

    Evidence (transcript, before/after state, role assignments, and summary.json) is written to a UTC
    timestamped subfolder under logDirectory. No tokens or credentials are saved to disk.

.PARAMETER ConfigPath
    Required. Path to the JSON configuration file describing the target cluster and timeouts. Keep this
    file outside the script directory.

.PARAMETER ResumeFrom
    Stage from which to start or resume execution:
      - Start (default): run all write steps (strip identity, assign identity, repair registration, verify sync).
      - AssignIdentity: skip the strip. If the resource already has a SystemAssigned identity, verify it is
        different from the previous principal (via -PreviousPrincipalId or a prior strip-succeeded summary.json)
        and use it without a PATCH. Use only after exit code 4, or after exit code 3 when the identity is absent.
      - RepairRegistration: skip ARM identity PATCH calls; start at Register-AzStackHCI -RepairRegistration
        (requires a SystemAssigned identity with a principalId on the resource).
      - Verify: skip PATCH and registration repair; only run Sync-AzureStackHCI and watch for connection
        (requires a SystemAssigned identity with a principalId on the resource).

.PARAMETER PreviousPrincipalId
    Optional GUID of the old system-assigned managed identity principal that was meant to be replaced.
    Used with -ResumeFrom AssignIdentity when a SystemAssigned identity is already present on the cluster
    resource and no earlier strip-succeeded summary.json is available in logDirectory.

.PARAMETER AcceptRoleAssignmentLoss
    Acknowledge that resetting the system-assigned managed identity deletes the old service principal,
    leaves any existing Azure RBAC role assignments as orphaned ("Identity not found") entries that are
    not deleted automatically, and provisions a new principal with none of those permissions. Pre-flight
    lists the old principal's role assignments at, above, and below the subscription scope (it does not
    check other subscriptions or non-RBAC grants such as Key Vault access policies or Microsoft Graph app
    roles) and exports them to role-assignments-before.json when -ResumeFrom Start is used. Without this
    switch, pre-flight stops with exit code 1 when the old principal has role assignments.

.PARAMETER AllowRepeatReplacement
    Allow a -ResumeFrom Start run to replace the cluster's system-assigned managed identity even when its
    current principalId matches the newPrincipalId recorded in an earlier summary.json under logDirectory.
    By default, pre-flight stops with exit code 1 in this situation and advises resuming with
    -ResumeFrom RepairRegistration or contacting Microsoft Support if registration repair keeps failing.

.EXAMPLE
    .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -WhatIf

    Runs all read-only pre-flight checks and shows the planned write steps without modifying Azure or the node.

.EXAMPLE
    .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json

    Runs pre-flight checks, prompts for confirmation, resets the cluster managed identity, repairs
    registration, and verifies synchronization.

.EXAMPLE
    .\Repair-AzureLocalClusterIdentity.ps1 -ConfigPath C:\ClusterRepair\cluster-identity-repair.json -ResumeFrom AssignIdentity

    Resumes from assigning the SystemAssigned identity if a previous run removed the old identity (exit code 4).

.NOTES
    Exit codes:
      0 - Success (or -WhatIf completed with no write).
      1 - Pre-flight check failed; nothing was changed.
      2 - Operator declined a confirmation prompt; the declined step did not run, while earlier confirmed steps stay done.
      3 - Removing the identity failed or its result is unknown (one read-only GET logs the current identity).
      4 - Assigning the new identity failed or timed out; the cluster may have NO identity (resume with -ResumeFrom AssignIdentity).
      5 - Register-AzStackHCI -RepairRegistration failed, threw an error, or did not return Result : Success (resume with -ResumeFrom RepairRegistration).
      6 - Sync-AzureStackHCI failed or the cluster did not report Connected with a newer LastConnected within syncWatchMinutes (resume with -ResumeFrom Verify).
      7 - Configuration file missing or invalid (checked before any Azure call or transcript start).

    Disclaimer: Provided as-is without warranty. Microsoft recommends opening a support request to confirm
    that your cluster matches this known issue before resetting its managed identity. Deleting the old
    system-assigned managed identity does not delete its Azure RBAC role assignments; they remain as
    orphaned ("Identity not found") entries, and the new principal has none of them. Recreate needed
    role assignments for the new principal and clean up the orphaned ones manually.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$ConfigPath,

    [Parameter()]
    [ValidateSet('Start', 'AssignIdentity', 'RepairRegistration', 'Verify')]
    [string]$ResumeFrom = 'Start',

    [Parameter()]
    [string]$PreviousPrincipalId,

    [Parameter()]
    [switch]$AcceptRoleAssignmentLoss,

    [Parameter()]
    [switch]$AllowRepeatReplacement
)

$script:RepairScriptPath = $PSCommandPath
if ([string]::IsNullOrWhiteSpace($script:RepairScriptPath)) {
    $script:RepairScriptPath = $MyInvocation.MyCommand.Path
}

function Get-UtcTimestamp {
    [CmdletBinding()]
    param()
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Write-RepairLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Operator console output must not pollute the integer exit-code return pipeline.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $line = "[$(Get-UtcTimestamp)] [$Level] $Message"
    $color = switch ($Level) {
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Cyan' }
    }
    Write-Host $line -ForegroundColor $color
    Write-Verbose $line
}

function Test-IsAdministrator {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $identity) { return $false }
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Read-RepairConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "Parameter -ConfigPath is required."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }

    $rawText = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($rawText)) {
        throw "Configuration file is empty: $Path"
    }

    try {
        $rawObj = $rawText | ConvertFrom-Json
    } catch {
        throw "Configuration file is not valid JSON: $($_.Exception.Message)"
    }

    if ($null -eq $rawObj) {
        throw "Configuration file parsed to null: $Path"
    }

    $requiredKeys = @('tenantId', 'subscriptionId', 'resourceGroupName', 'clusterName', 'region')
    $optionalDefaults = [ordered]@{
        apiVersion             = '2024-02-15-preview'
        expectedCloudId        = $null
        logDirectory           = 'C:\Temp\ClusterIdentityRepair'
        pollIntervalSeconds    = 10
        identityTimeoutSeconds = 300
        propagationWaitSeconds = 60
        syncWatchMinutes       = 10
    }
    $allowedKeys = $requiredKeys + @($optionalDefaults.Keys)

    $presentProperties = @($rawObj.PSObject.Properties)
    $presentNames = @($presentProperties | ForEach-Object { $_.Name })

    foreach ($name in $presentNames) {
        if ($allowedKeys -notcontains $name) {
            throw "Unknown configuration key '$name'."
        }
    }

    $config = [ordered]@{}
    foreach ($req in $requiredKeys) {
        $prop = $presentProperties | Where-Object { $_.Name -ceq $req } | Select-Object -First 1
        if ($null -eq $prop) {
            $prop = $presentProperties | Where-Object { $_.Name -ieq $req } | Select-Object -First 1
        }
        if ($null -eq $prop -or $null -eq $prop.Value -or [string]::IsNullOrWhiteSpace("$($prop.Value)")) {
            throw "Missing or empty required configuration field '$req'."
        }
        $config[$req] = "$($prop.Value)".Trim()
    }

    foreach ($opt in $optionalDefaults.Keys) {
        $prop = $presentProperties | Where-Object { $_.Name -ieq $opt } | Select-Object -First 1
        if ($null -ne $prop -and $null -ne $prop.Value -and "$($prop.Value)" -ne '') {
            $config[$opt] = $prop.Value
        } else {
            $config[$opt] = $optionalDefaults[$opt]
        }
    }

    $parsedGuid = [guid]::Empty
    foreach ($guidKey in @('tenantId', 'subscriptionId')) {
        if (-not [guid]::TryParse("$($config[$guidKey])", [ref]$parsedGuid)) {
            throw "Configuration field '$guidKey' must be a valid GUID (got '$($config[$guidKey])')."
        }
    }

    if ($null -ne $config.expectedCloudId -and "$($config.expectedCloudId)" -ne '') {
        $config.expectedCloudId = "$($config.expectedCloudId)".Trim()
        if (-not [guid]::TryParse($config.expectedCloudId, [ref]$parsedGuid)) {
            throw "Configuration field 'expectedCloudId' must be a valid GUID when set (got '$($config.expectedCloudId)')."
        }
    } else {
        $config.expectedCloudId = $null
    }

    $config.apiVersion = "$($config.apiVersion)".Trim()
    $config.logDirectory = "$($config.logDirectory)".Trim()
    if ([string]::IsNullOrWhiteSpace($config.apiVersion) -or [string]::IsNullOrWhiteSpace($config.logDirectory)) {
        throw "Configuration fields 'apiVersion' and 'logDirectory' cannot be empty."
    }

    if ($config.resourceGroupName -notmatch '^[-\w\._\(\)]{1,90}$' -or $config.resourceGroupName.EndsWith('.')) {
        throw "Configuration field 'resourceGroupName' is invalid (got '$($config.resourceGroupName)')."
    }
    if ($config.clusterName -notmatch '^[A-Za-z0-9._-]+$') {
        throw "Configuration field 'clusterName' contains invalid characters (got '$($config.clusterName)')."
    }
    if ($config.region -notmatch '^[A-Za-z0-9]+$') {
        throw "Configuration field 'region' must contain only letters and digits (got '$($config.region)')."
    }
    if ($config.apiVersion -notmatch '^\d{4}-\d{2}-\d{2}(-preview)?$') {
        throw "Configuration field 'apiVersion' is invalid (got '$($config.apiVersion)')."
    }

    foreach ($intKey in @('pollIntervalSeconds', 'identityTimeoutSeconds', 'syncWatchMinutes')) {
        $val = 0
        if (-not [int]::TryParse("$($config[$intKey])", [ref]$val) -or $val -le 0) {
            throw "Configuration field '$intKey' must be a positive integer."
        }
        $config[$intKey] = $val
    }

    $propWait = 0
    if (-not [int]::TryParse("$($config.propagationWaitSeconds)", [ref]$propWait) -or $propWait -lt 0) {
        throw "Configuration field 'propagationWaitSeconds' must be a non-negative integer."
    }
    $config.propagationWaitSeconds = $propWait

    return [pscustomobject]$config
}

function ConvertFrom-JsonSafe {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Content
    )
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $null
    }
    try {
        return ($Content | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )
    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in $InputObject.Keys) {
            if ("$k" -ieq $PropertyName) {
                return $InputObject[$k]
            }
        }
        return $null
    }
    $prop = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq $PropertyName } | Select-Object -First 1
    if ($null -ne $prop) {
        return $prop.Value
    }
    return $null
}

function Get-ResponseHeaderValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Headers,

        [Parameter(Mandatory = $true)]
        [string]$HeaderName
    )
    if ($null -eq $Headers) {
        return $null
    }
    $rawVal = $null
    if ($Headers -is [System.Collections.IDictionary]) {
        foreach ($k in $Headers.Keys) {
            if ("$k" -ieq $HeaderName) {
                $rawVal = $Headers[$k]
                break
            }
        }
    } elseif ($null -ne $Headers.PSObject) {
        $prop = $Headers.PSObject.Properties | Where-Object { $_.Name -ieq $HeaderName } | Select-Object -First 1
        if ($null -ne $prop) {
            $rawVal = $prop.Value
        } elseif ($Headers -is [System.Collections.IEnumerable]) {
            foreach ($item in $Headers) {
                $itemKey = Get-ObjectPropertyValue -InputObject $item -PropertyName 'Key'
                if ("$itemKey" -ieq $HeaderName) {
                    $rawVal = Get-ObjectPropertyValue -InputObject $item -PropertyName 'Value'
                    break
                }
            }
        }
    }

    if ($null -eq $rawVal) {
        return $null
    }
    if ($rawVal -is [System.Collections.IEnumerable] -and -not ($rawVal -is [string])) {
        foreach ($element in $rawVal) {
            if (-not [string]::IsNullOrWhiteSpace("$element")) {
                return "$element".Trim()
            }
        }
        return $null
    }
    if ([string]::IsNullOrWhiteSpace("$rawVal")) {
        return $null
    }
    return "$rawVal".Trim()
}

function Test-HasJsonValueArray {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        $InputObject
    )
    if ($null -eq $InputObject) {
        return $false
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in $InputObject.Keys) {
            if ("$k" -ieq 'value') {
                $v = $InputObject[$k]
                return ($null -ne $v -and -not ($v -is [string]) -and ($v -is [System.Collections.IEnumerable]))
            }
        }
        return $false
    }
    $prop = $InputObject.PSObject.Properties | Where-Object { $_.Name -ieq 'value' } | Select-Object -First 1
    if ($null -eq $prop -or $null -eq $prop.Value) {
        return $false
    }
    return (-not ($prop.Value -is [string]) -and ($prop.Value -is [System.Collections.IEnumerable]))
}

function Get-RetryAfterSecond {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter()]
        $Headers,

        [Parameter()]
        [int]$DefaultSeconds = 0
    )
    $raw = Get-ResponseHeaderValue -Headers $Headers -HeaderName 'Retry-After'
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $sec = 0
        if ([int]::TryParse($raw, [ref]$sec) -and $sec -gt 0) {
            return $sec
        }
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse($raw, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$dt)) {
            $diff = [int][Math]::Ceiling(($dt - (Get-Date).ToUniversalTime()).TotalSeconds)
            if ($diff -gt 0) {
                return $diff
            }
        }
    }
    return $DefaultSeconds
}

function Test-BudgetActive {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Budget
    )
    $elapsedWall = ((Get-Date).ToUniversalTime() - $Budget.StartedUtc).TotalSeconds
    $used = [Math]::Max([double]$Budget.WaitedSeconds, $elapsedWall)
    return ($used -lt $Budget.TimeoutSeconds)
}

function Invoke-BudgetedWait {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Budget,

        [Parameter(Mandatory = $true)]
        [int]$RequestedSeconds
    )
    $elapsedWall = ((Get-Date).ToUniversalTime() - $Budget.StartedUtc).TotalSeconds
    $used = [Math]::Max([double]$Budget.WaitedSeconds, $elapsedWall)
    $remaining = [int][Math]::Floor($Budget.TimeoutSeconds - $used)
    if ($remaining -le 0) {
        return $false
    }
    if ($RequestedSeconds -le 0) {
        return $true
    }
    $waitSec = [Math]::Min($RequestedSeconds, $remaining)
    $Budget.WaitedSeconds += $waitSec
    $null = Start-Sleep -Seconds $waitSec
    if ($waitSec -lt $RequestedSeconds) {
        $Budget.WaitedSeconds = $Budget.TimeoutSeconds
        return $false
    }
    return (Test-BudgetActive -Budget $Budget)
}

function Confirm-TargetAzContext {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    $azCtx = $null
    try {
        $azCtx = Get-AzContext
    } catch {
        $azCtx = $null
    }
    $ctxTenant = $null
    $ctxSub = $null
    if ($null -ne $azCtx) {
        $tenantObj = Get-ObjectPropertyValue -InputObject $azCtx -PropertyName 'Tenant'
        $subObj = Get-ObjectPropertyValue -InputObject $azCtx -PropertyName 'Subscription'
        $ctxTenant = "$(Get-ObjectPropertyValue -InputObject $tenantObj -PropertyName 'Id')"
        $ctxSub = "$(Get-ObjectPropertyValue -InputObject $subObj -PropertyName 'Id')"
    }

    if ($null -eq $azCtx -or $ctxTenant -ine $TenantId -or $ctxSub -ine $SubscriptionId) {
        Write-RepairLog -Message "Azure context does not match tenant '$TenantId' and subscription '$SubscriptionId'. Calling Connect-AzAccount with device authentication..."
        try {
            $null = Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -UseDeviceAuthentication -WhatIf:$false -Confirm:$false
        } catch {
            Write-RepairLog -Level ERROR -Message "Connect-AzAccount failed: $($_.Exception.Message)"
            return $false
        }

        try {
            $azCtx = Get-AzContext
        } catch {
            $azCtx = $null
        }
        $ctxTenant = $null
        $ctxSub = $null
        if ($null -ne $azCtx) {
            $tenantObj = Get-ObjectPropertyValue -InputObject $azCtx -PropertyName 'Tenant'
            $subObj = Get-ObjectPropertyValue -InputObject $azCtx -PropertyName 'Subscription'
            $ctxTenant = "$(Get-ObjectPropertyValue -InputObject $tenantObj -PropertyName 'Id')"
            $ctxSub = "$(Get-ObjectPropertyValue -InputObject $subObj -PropertyName 'Id')"
        }
        if ($null -eq $azCtx -or $ctxTenant -ine $TenantId -or $ctxSub -ine $SubscriptionId) {
            Write-RepairLog -Level ERROR -Message "Azure context after sign-in (Tenant='$ctxTenant', Subscription='$ctxSub') still does not match configuration."
            return $false
        }
    }
    return $true
}

function Invoke-ArmRestRequest {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,

        [Parameter()]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter()]
        [string]$Payload
    )
    $savedConfirm = $ConfirmPreference
    try {
        $ConfirmPreference = 'None'
        $cmd = Get-Command -Name 'Invoke-AzRestMethod' -ErrorAction SilentlyContinue
        $hasConfirm = ($null -ne $cmd -and $null -ne $cmd.Parameters -and $cmd.Parameters.ContainsKey('Confirm'))
        $splat = @{ Method = $Method }
        if (-not [string]::IsNullOrWhiteSpace($Uri)) {
            $splat['Uri'] = $Uri
        } else {
            $splat['Path'] = $Path
        }
        if ($PSBoundParameters.ContainsKey('Payload') -and $null -ne $Payload) {
            $splat['Payload'] = $Payload
        }
        if ($hasConfirm) {
            $splat['Confirm'] = $false
        }
        return (Invoke-AzRestMethod @splat)
    } finally {
        $ConfirmPreference = $savedConfirm
    }
}

function Show-ClusterIdentityState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClusterPath
    )
    try {
        $resp = Invoke-ArmRestRequest -Path $ClusterPath -Method GET
        $code = [int](Get-ObjectPropertyValue -InputObject $resp -PropertyName 'StatusCode')
        if ($code -ne 200) {
            Write-RepairLog -Level WARN -Message "Read-only state check after strip failure returned HTTP $code; current identity state in Azure is unknown. Perform a read-only check before choosing a -ResumeFrom stage."
            return
        }
        $body = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $resp -PropertyName 'Content')
        $resId = "$(Get-ObjectPropertyValue -InputObject $body -PropertyName 'id')"
        if ($null -eq $body -or [string]::IsNullOrWhiteSpace($resId)) {
            Write-RepairLog -Level WARN -Message "Read-only state check after strip failure returned an unparsable resource body; current identity state in Azure is unknown. Perform a read-only check before choosing a -ResumeFrom stage."
            return
        }
        $idObj = Get-ObjectPropertyValue -InputObject $body -PropertyName 'identity'
        if ($null -eq $idObj) {
            Write-RepairLog -Level WARN -Message "Read-only state check shows cluster resource currently has no identity object (identity is absent/null). Check state before choosing -ResumeFrom AssignIdentity."
            return
        }
        $idType = "$(Get-ObjectPropertyValue -InputObject $idObj -PropertyName 'type')"
        $idPid = "$(Get-ObjectPropertyValue -InputObject $idObj -PropertyName 'principalId')"
        Write-RepairLog -Level WARN -Message "Read-only state check shows cluster identity type='$idType', principalId='$idPid'. Verify state before choosing a -ResumeFrom stage."
    } catch {
        Write-RepairLog -Level WARN -Message "Read-only state check after strip failure threw an error ($($_.Exception.Message)); current identity state in Azure is unknown."
    }
}

function Wait-ArmAsyncOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationUri,

        [Parameter()]
        [ValidateSet('AzureAsyncOperation', 'Location')]
        [string]$Protocol = 'AzureAsyncOperation',

        [Parameter(Mandatory = $true)]
        [int]$PollIntervalSeconds,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutSeconds,

        [Parameter()]
        [int]$InitialWaitSeconds = 0,

        [Parameter()]
        [hashtable]$Budget
    )
    if ($null -eq $Budget) {
        $Budget = @{
            StartedUtc     = (Get-Date).ToUniversalTime()
            TimeoutSeconds = $TimeoutSeconds
            WaitedSeconds  = 0
        }
    }
    if ($InitialWaitSeconds -gt 0) {
        if (-not (Invoke-BudgetedWait -Budget $Budget -RequestedSeconds $InitialWaitSeconds)) {
            Write-RepairLog -Level ERROR -Message "Timed out waiting for async operation initial delay at $OperationUri after $($Budget.TimeoutSeconds) seconds."
            return $false
        }
    }
    $maxIterations = [Math]::Max(1, [int][Math]::Ceiling($Budget.TimeoutSeconds / [double]$PollIntervalSeconds) + 2)
    $currentUri = $OperationUri
    for ($i = 1; $i -le $maxIterations; $i++) {
        if (-not (Test-BudgetActive -Budget $Budget)) {
            break
        }
        $resp = $null
        try {
            $resp = Invoke-ArmRestRequest -Uri $currentUri -Method GET
        } catch {
            Write-RepairLog -Level WARN -Message "Async operation poll threw a transport error ($($_.Exception.Message)); retrying..."
            if ($i -lt $maxIterations -and (Invoke-BudgetedWait -Budget $Budget -RequestedSeconds $PollIntervalSeconds)) {
                continue
            }
            return $false
        }

        if (-not (Test-BudgetActive -Budget $Budget)) {
            break
        }

        $statusCode = [int](Get-ObjectPropertyValue -InputObject $resp -PropertyName 'StatusCode')
        $headers = Get-ObjectPropertyValue -InputObject $resp -PropertyName 'Headers'
        $sleepSec = Get-RetryAfterSecond -Headers $headers -DefaultSeconds $PollIntervalSeconds

        if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -lt 600)) {
            Write-RepairLog -Level WARN -Message "Async operation poll returned HTTP $statusCode from $currentUri; retrying..."
            if ($i -lt $maxIterations -and (Invoke-BudgetedWait -Budget $Budget -RequestedSeconds $sleepSec)) {
                continue
            }
            return $false
        }

        if ($Protocol -eq 'Location') {
            if ($statusCode -eq 202) {
                $nextLoc = Get-ResponseHeaderValue -Headers $headers -HeaderName 'Location'
                if (-not [string]::IsNullOrWhiteSpace($nextLoc)) {
                    $currentUri = $nextLoc
                }
                if ($i -lt $maxIterations -and (Invoke-BudgetedWait -Budget $Budget -RequestedSeconds $sleepSec)) {
                    continue
                }
                break
            }
            if ($statusCode -in @(200, 204)) {
                $body = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $resp -PropertyName 'Content')
                if ($null -ne $body) {
                    $errObj = Get-ObjectPropertyValue -InputObject $body -PropertyName 'error'
                    $statusVal = "$(Get-ObjectPropertyValue -InputObject $body -PropertyName 'status')"
                    $propsObj = Get-ObjectPropertyValue -InputObject $body -PropertyName 'properties'
                    $provState = "$(Get-ObjectPropertyValue -InputObject $propsObj -PropertyName 'provisioningState')"
                    if ($null -ne $errObj -or $statusVal -in @('Failed', 'Canceled', 'Cancelled') -or $provState -in @('Failed', 'Canceled', 'Cancelled')) {
                        Write-RepairLog -Level ERROR -Message "Location poll returned terminal failure in body from $currentUri."
                        return $false
                    }
                }
                return $true
            }
            Write-RepairLog -Level ERROR -Message "Location operation poll failed with HTTP $statusCode from $currentUri."
            return $false
        }

        if ($statusCode -lt 200 -or $statusCode -ge 300) {
            Write-RepairLog -Level ERROR -Message "Async operation poll failed with HTTP $statusCode from $currentUri."
            return $false
        }
        $body = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $resp -PropertyName 'Content')
        $status = "$(Get-ObjectPropertyValue -InputObject $body -PropertyName 'status')"
        if ([string]::IsNullOrWhiteSpace($status)) {
            $props = Get-ObjectPropertyValue -InputObject $body -PropertyName 'properties'
            $status = "$(Get-ObjectPropertyValue -InputObject $props -PropertyName 'provisioningState')"
        }
        if ($status -ieq 'Succeeded') {
            return $true
        }
        if ($status -in @('Failed', 'Canceled', 'Cancelled')) {
            Write-RepairLog -Level ERROR -Message "Async operation reported terminal status '$status' at $currentUri."
            return $false
        }
        if (-not ($i -lt $maxIterations -and (Invoke-BudgetedWait -Budget $Budget -RequestedSeconds $sleepSec))) {
            break
        }
    }
    Write-RepairLog -Level ERROR -Message "Timed out waiting for async operation at $currentUri after $($Budget.TimeoutSeconds) seconds."
    return $false
}

function Get-PreviousStripSummaryState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogDirectory
    )
    $allOldPids = New-Object System.Collections.ArrayList
    $allNewPids = New-Object System.Collections.ArrayList
    $unverifiedNewPids = New-Object System.Collections.ArrayList
    $latestSucceededOldPid = $null
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        return [pscustomobject]@{
            AllOldPrincipalIds          = @()
            AllNewPrincipalIds          = @()
            UnverifiedNewPrincipalIds   = @()
            LatestSucceededOldPrincipal = $null
        }
    }
    $dirs = @(
        Get-ChildItem -LiteralPath $LogDirectory -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d{8}T\d{6}Z-[0-9a-fA-F]{8}$' } |
            Sort-Object Name -Descending
    )
    foreach ($d in $dirs) {
        $summaryPath = Join-Path -Path $d.FullName -ChildPath 'summary.json'
        if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
            continue
        }
        try {
            $raw = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8
            $obj = ConvertFrom-JsonSafe -Content $raw
            if ($null -eq $obj) { continue }
            $oldPid = "$(Get-ObjectPropertyValue -InputObject $obj -PropertyName 'oldPrincipalId')".Trim()
            $parsed = [guid]::Empty
            $validPid = (-not [string]::IsNullOrWhiteSpace($oldPid) -and [guid]::TryParse($oldPid, [ref]$parsed))
            if ($validPid) {
                [void]$allOldPids.Add($oldPid)
            }
            $newPid = "$(Get-ObjectPropertyValue -InputObject $obj -PropertyName 'newPrincipalId')".Trim()
            $parsedNew = [guid]::Empty
            $validNewPid = (-not [string]::IsNullOrWhiteSpace($newPid) -and [guid]::TryParse($newPid, [ref]$parsedNew))
            if ($validNewPid) {
                [void]$allNewPids.Add($newPid)
                $summaryExit = [int](Get-ObjectPropertyValue -InputObject $obj -PropertyName 'exitCode')
                if ($summaryExit -ne 0) {
                    [void]$unverifiedNewPids.Add($newPid)
                }
            }
            if ($null -eq $latestSucceededOldPid -and $validPid) {
                $stepsArr = @(Get-ObjectPropertyValue -InputObject $obj -PropertyName 'steps')
                foreach ($st in $stepsArr) {
                    if ($null -eq $st) { continue }
                    $sName = "$(Get-ObjectPropertyValue -InputObject $st -PropertyName 'name')"
                    $sStatus = "$(Get-ObjectPropertyValue -InputObject $st -PropertyName 'status')"
                    if ($sName -ieq 'StripIdentity' -and $sStatus -ieq 'Succeeded') {
                        $latestSucceededOldPid = $oldPid
                        break
                    }
                }
            }
        } catch {
            continue
        }
    }
    return [pscustomobject]@{
        AllOldPrincipalIds          = $allOldPids.ToArray()
        AllNewPrincipalIds          = $allNewPids.ToArray()
        UnverifiedNewPrincipalIds   = $unverifiedNewPids.ToArray()
        LatestSucceededOldPrincipal = $latestSucceededOldPid
    }
}

function Protect-EvidenceDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return
    }
    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $flags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propFlags = [System.Security.AccessControl.PropagationFlags]::None
        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $rights, $flags, $propFlags, $allow)
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $LiteralPath -AclObject $acl -ErrorAction Stop
    } catch {
        Write-RepairLog -Level WARN -Message "Could not restrict ACL on evidence folder '$LiteralPath': $($_.Exception.Message)"
    }
}

function Invoke-ClusterIdentityRepair {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ConfigPath,

        [Parameter()]
        [ValidateSet('Start', 'AssignIdentity', 'RepairRegistration', 'Verify')]
        [string]$ResumeFrom = 'Start',

        [Parameter()]
        [string]$PreviousPrincipalId,

        [Parameter()]
        [switch]$AcceptRoleAssignmentLoss,

        [Parameter()]
        [switch]$AllowRepeatReplacement
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # 1. Validate configuration before creating files, starting transcript, or calling Azure.
    $cfg = $null
    try {
        $cfg = Read-RepairConfig -Path $ConfigPath
    } catch {
        Write-RepairLog -Level ERROR -Message "Configuration validation failed: $($_.Exception.Message)"
        return 7
    }

    if (-not [string]::IsNullOrWhiteSpace($PreviousPrincipalId)) {
        $PreviousPrincipalId = $PreviousPrincipalId.Trim()
        $parsedPrevGuid = [guid]::Empty
        if (-not [guid]::TryParse($PreviousPrincipalId, [ref]$parsedPrevGuid)) {
            Write-RepairLog -Level ERROR -Message "Parameter -PreviousPrincipalId must be a valid GUID (got '$PreviousPrincipalId')."
            return 7
        }
    }

    # 2. Administrator check before creating or protecting any evidence folder.
    $isAdmin = $false
    try {
        $isAdmin = [bool](Test-IsAdministrator)
    } catch {
        Write-RepairLog -Level ERROR -Message "Pre-flight failed: Administrator check threw an error: $($_.Exception.Message)"
        return 1
    }
    if (-not $isAdmin) {
        Write-RepairLog -Level ERROR -Message "Pre-flight failed: PowerShell session is not running as Administrator."
        return 1
    }

    $resolvedConfigPath = $ConfigPath
    try {
        $resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).ProviderPath
    } catch {
        $resolvedConfigPath = $ConfigPath
    }
    $selfScriptPath = $script:RepairScriptPath
    if ([string]::IsNullOrWhiteSpace($selfScriptPath)) {
        $selfScriptPath = $PSCommandPath
    }
    $escapedScriptPath = "$selfScriptPath".Replace("'", "''")
    $escapedConfigPath = "$resolvedConfigPath".Replace("'", "''")
    $resumeAssignCmd = "& '$escapedScriptPath' -ConfigPath '$escapedConfigPath' -ResumeFrom AssignIdentity"
    $resumeRepairCmd = "& '$escapedScriptPath' -ConfigPath '$escapedConfigPath' -ResumeFrom RepairRegistration"
    $resumeVerifyCmd = "& '$escapedScriptPath' -ConfigPath '$escapedConfigPath' -ResumeFrom Verify"

    $startedUtc = Get-UtcTimestamp
    $folderStamp = "{0}-{1}" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $runDir = Join-Path -Path $cfg.logDirectory -ChildPath $folderStamp
    $savedWhatIf = $WhatIfPreference
    $savedConfirm = $ConfirmPreference
    try {
        $WhatIfPreference = $false
        $ConfirmPreference = 'None'
        $logRootExisted = Test-Path -LiteralPath $cfg.logDirectory -PathType Container
        if (-not $logRootExisted) {
            $null = New-Item -ItemType Directory -Path $cfg.logDirectory -Force
            Protect-EvidenceDirectory -LiteralPath $cfg.logDirectory
        }
        $null = New-Item -ItemType Directory -Path $runDir -Force
        Protect-EvidenceDirectory -LiteralPath $runDir
    } finally {
        $WhatIfPreference = $savedWhatIf
        $ConfirmPreference = $savedConfirm
    }

    $transcriptStarted = $false
    $transcriptStartError = $null
    $transcriptPath = Join-Path -Path $runDir -ChildPath 'transcript.txt'
    try {
        $WhatIfPreference = $false
        $ConfirmPreference = 'None'
        $null = Start-Transcript -LiteralPath $transcriptPath -Force
        $transcriptStarted = $true
    } catch {
        $transcriptStartError = $_.Exception.Message
    } finally {
        $WhatIfPreference = $savedWhatIf
        $ConfirmPreference = $savedConfirm
    }

    $exitCode = -1
    $currentStage = 'Preflight'
    $oldPrincipalId = $null
    $newPrincipalId = $null
    $steps = New-Object System.Collections.ArrayList

    $recordStep = {
        param([string]$Name, [string]$Status)
        [void]$steps.Add([pscustomobject]@{
            name   = $Name
            status = $Status
            utc    = (Get-UtcTimestamp)
        })
    }

    try {
        & $recordStep 'Preflight-Administrator' 'Succeeded'
        Write-RepairLog -Message "Starting Azure Local cluster identity repair (ResumeFrom=$ResumeFrom). Evidence folder: $runDir"
        if ($transcriptStarted) {
            Write-RepairLog -Message "Do not paste tokens or credentials into this session; console output is recorded in transcript.txt."
        } else {
            Write-RepairLog -Level WARN -Message "Start-Transcript could not be started ($transcriptStartError); console output is NOT recorded in transcript.txt. Do not paste tokens or credentials into this session."
        }

        # Required modules and minimum versions check (installed and loaded)
        $requiredModules = @(
            @{ Name = 'Az.Accounts';  MinVersion = [version]'2.11.2' },
            @{ Name = 'Az.Resources'; MinVersion = [version]'6.2.0' },
            @{ Name = 'Az.StackHCI';  MinVersion = $null }
        )
        foreach ($modReq in $requiredModules) {
            $availMods = @(Get-Module -ListAvailable -Name $modReq.Name -ErrorAction SilentlyContinue)
            $highestMod = $availMods | Sort-Object Version -Descending | Select-Object -First 1
            if ($null -eq $highestMod) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Required module '$($modReq.Name)' is not installed."
                & $recordStep 'Preflight-Modules' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            if ($null -ne $modReq.MinVersion -and [version]$highestMod.Version -lt $modReq.MinVersion) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Module '$($modReq.Name)' version $($highestMod.Version) is older than required minimum version $($modReq.MinVersion)."
                & $recordStep 'Preflight-Modules' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            if ($null -ne $modReq.MinVersion) {
                $loadedMods = @(Get-Module -Name $modReq.Name -ErrorAction SilentlyContinue)
                foreach ($loadedMod in $loadedMods) {
                    if ($null -ne $loadedMod -and $null -ne $loadedMod.Version -and [version]$loadedMod.Version -lt $modReq.MinVersion) {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: Loaded module '$($modReq.Name)' version $($loadedMod.Version) in current session is older than required minimum version $($modReq.MinVersion)."
                        & $recordStep 'Preflight-Modules' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }
                }
            }
        }
        & $recordStep 'Preflight-Modules' 'Succeeded'

        # Required commands check
        $requiredCommands = @(
            'Invoke-AzRestMethod',
            'Connect-AzAccount',
            'Get-AzContext',
            'Register-AzStackHCI',
            'Get-AzureStackHCI',
            'Sync-AzureStackHCI',
            'Get-ClusterNode'
        )
        foreach ($cmdName in $requiredCommands) {
            if (-not (Get-Command -Name $cmdName -ErrorAction SilentlyContinue)) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Required command '$cmdName' was not found. Ensure Az.Accounts, Az.Resources, Az.StackHCI, AzureStackHCI, and FailoverClusters modules are installed."
                & $recordStep 'Preflight-Commands' 'Failed'
                $exitCode = 1
                return $exitCode
            }
        }

        # 3. Cluster node check
        $clusterNodes = $null
        try {
            $clusterNodes = @(Get-ClusterNode)
        } catch {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Get-ClusterNode threw an error: $($_.Exception.Message)"
            & $recordStep 'Preflight-ClusterNode' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $localNames = @($env:COMPUTERNAME, [Environment]::MachineName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $nodeMatched = $false
        foreach ($n in $clusterNodes) {
            $nName = "$(Get-ObjectPropertyValue -InputObject $n -PropertyName 'Name')"
            $nNameShort = ($nName -split '\.')[0]
            foreach ($localName in $localNames) {
                $localShort = ($localName -split '\.')[0]
                if ($nName -ieq $localName -or $nNameShort -ieq $localShort) {
                    $nodeMatched = $true
                    break
                }
            }
            if ($nodeMatched) { break }
        }
        if (-not $nodeMatched) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Local machine is not listed in Get-ClusterNode output."
            & $recordStep 'Preflight-ClusterNode' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        foreach ($n in $clusterNodes) {
            $nName = "$(Get-ObjectPropertyValue -InputObject $n -PropertyName 'Name')"
            $nState = "$(Get-ObjectPropertyValue -InputObject $n -PropertyName 'State')"
            if (-not [string]::IsNullOrWhiteSpace($nState) -and $nState -ine 'Up') {
                Write-RepairLog -Level WARN -Message "Cluster node '$nName' has State='$nState' (not 'Up'). Register-AzStackHCI -RepairRegistration replaces certificates on every node; a down node may leave registration partially repaired."
            }
        }
        & $recordStep 'Preflight-ClusterNode' 'Succeeded'

        # 4. Local Get-AzureStackHCI registration check
        $hciBefore = $null
        try {
            $hciBefore = Get-AzureStackHCI
        } catch {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Get-AzureStackHCI threw an error: $($_.Exception.Message)"
            & $recordStep 'Preflight-LocalRegistration' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $regStatus = "$(Get-ObjectPropertyValue -InputObject $hciBefore -PropertyName 'RegistrationStatus')"
        if ($regStatus -ine 'Registered') {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Get-AzureStackHCI RegistrationStatus is '$regStatus' (expected 'Registered')."
            & $recordStep 'Preflight-LocalRegistration' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $expectedResourceId = "/subscriptions/$($cfg.subscriptionId)/resourceGroups/$($cfg.resourceGroupName)/providers/Microsoft.AzureStackHCI/clusters/$($cfg.clusterName)"
        $actualResourceUri = "$(Get-ObjectPropertyValue -InputObject $hciBefore -PropertyName 'AzureResourceUri')"
        if ($actualResourceUri.Trim('/') -ine $expectedResourceId.Trim('/')) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Local AzureResourceUri '$actualResourceUri' does not match configured resource '$expectedResourceId'."
            & $recordStep 'Preflight-LocalRegistration' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $rawLastConnected = Get-ObjectPropertyValue -InputObject $hciBefore -PropertyName 'LastConnected'
        $beforeLastConnectedUtc = $null
        if ($null -ne $rawLastConnected -and "$rawLastConnected" -ne '') {
            $beforeLastConnectedUtc = ([datetime]$rawLastConnected).ToUniversalTime()
        }
        & $recordStep 'Preflight-LocalRegistration' 'Succeeded'

        # 5. Azure context check
        if (-not (Confirm-TargetAzContext -TenantId $cfg.tenantId -SubscriptionId $cfg.subscriptionId)) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Could not establish target Azure context."
            & $recordStep 'Preflight-AzureContext' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        & $recordStep 'Preflight-AzureContext' 'Succeeded'

        # 6. GET the cluster resource
        $clusterPath = "$expectedResourceId`?api-version=$($cfg.apiVersion)"
        $getClusterResp = $null
        try {
            $getClusterResp = Invoke-ArmRestRequest -Path $clusterPath -Method GET
        } catch {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET cluster resource threw an error: $($_.Exception.Message)"
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        $getClusterCode = [int](Get-ObjectPropertyValue -InputObject $getClusterResp -PropertyName 'StatusCode')
        if ($getClusterCode -ne 200) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET cluster resource '$expectedResourceId' returned HTTP $getClusterCode."
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $clusterBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $getClusterResp -PropertyName 'Content')
        $clusterResId = "$(Get-ObjectPropertyValue -InputObject $clusterBody -PropertyName 'id')"
        if ($null -eq $clusterBody -or [string]::IsNullOrWhiteSpace($clusterResId)) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster resource GET returned an empty or invalid JSON body."
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $resourceLocation = "$(Get-ObjectPropertyValue -InputObject $clusterBody -PropertyName 'location')"
        if ($resourceLocation -ine $cfg.region) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster resource location '$resourceLocation' does not match configured region '$($cfg.region)'."
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $clusterProps = Get-ObjectPropertyValue -InputObject $clusterBody -PropertyName 'properties'
        $actualCloudId = "$(Get-ObjectPropertyValue -InputObject $clusterProps -PropertyName 'cloudId')"
        if ($null -ne $cfg.expectedCloudId -and $actualCloudId -ine $cfg.expectedCloudId) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster properties.cloudId '$actualCloudId' does not match expectedCloudId '$($cfg.expectedCloudId)'."
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $identityObj = Get-ObjectPropertyValue -InputObject $clusterBody -PropertyName 'identity'
        $oldIdentityType = "$(Get-ObjectPropertyValue -InputObject $identityObj -PropertyName 'type')"
        $userAssignedObj = Get-ObjectPropertyValue -InputObject $identityObj -PropertyName 'userAssignedIdentities'
        if ($oldIdentityType -match '(?i)UserAssigned' -or $null -ne $userAssignedObj) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster resource has user-assigned managed identities (identity.type='$oldIdentityType'). Resetting identity to None would remove them and is out of scope."
            & $recordStep 'Preflight-GetClusterResource' 'Failed'
            $exitCode = 1
            return $exitCode
        }

        $rawOldPid = Get-ObjectPropertyValue -InputObject $identityObj -PropertyName 'principalId'
        $presentPrincipalId = $null
        if ($null -ne $rawOldPid -and -not [string]::IsNullOrWhiteSpace("$rawOldPid")) {
            $presentPrincipalId = "$rawOldPid".Trim()
        }
        if ($ResumeFrom -eq 'Start') {
            $oldPrincipalId = $presentPrincipalId
            if (-not [string]::IsNullOrWhiteSpace($presentPrincipalId) -and -not $AllowRepeatReplacement.IsPresent) {
                $priorState = Get-PreviousStripSummaryState -LogDirectory $cfg.logDirectory
                foreach ($priorNewPid in @($priorState.UnverifiedNewPrincipalIds)) {
                    if ($presentPrincipalId -ieq $priorNewPid) {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster identity ('$presentPrincipalId') matches a newPrincipalId already provisioned by an earlier incomplete run in '$($cfg.logDirectory)'. Do not strip the newly created identity; resume with '$resumeRepairCmd', or contact Microsoft Support if registration repair keeps failing (pass -AllowRepeatReplacement only if Microsoft Support asks for another identity reset)."
                        & $recordStep 'Preflight-RepeatReplacement' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }
                }
            }
        } elseif ($ResumeFrom -in @('RepairRegistration', 'Verify')) {
            if ($oldIdentityType -ine 'SystemAssigned' -or [string]::IsNullOrWhiteSpace($presentPrincipalId)) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: -ResumeFrom $ResumeFrom requires a SystemAssigned identity with a principalId on the cluster resource (found type='$oldIdentityType'). Resume with: $resumeAssignCmd"
                & $recordStep 'Preflight-GetClusterResource' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            $newPrincipalId = $presentPrincipalId
        }

        $beforeSnapshot = [ordered]@{
            capturedUtc       = (Get-UtcTimestamp)
            clusterResource   = $clusterBody
            localRegistration = [ordered]@{
                AzureResourceUri   = $actualResourceUri
                RegistrationStatus = $regStatus
                ConnectionStatus   = "$(Get-ObjectPropertyValue -InputObject $hciBefore -PropertyName 'ConnectionStatus')"
                LastConnected      = if ($null -ne $beforeLastConnectedUtc) { $beforeLastConnectedUtc.ToString('o') } else { $null }
            }
        }
        try {
            $WhatIfPreference = $false
            $ConfirmPreference = 'None'
            $beforeSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $runDir -ChildPath 'before.json') -Encoding UTF8
        } finally {
            $WhatIfPreference = $savedWhatIf
            $ConfirmPreference = $savedConfirm
        }
        & $recordStep 'Preflight-GetClusterResource' 'Succeeded'

        # 7. Locks check
        $locksPath = "$expectedResourceId/providers/Microsoft.Authorization/locks?api-version=2020-05-01"
        $locksResp = $null
        try {
            $locksResp = Invoke-ArmRestRequest -Path $locksPath -Method GET
        } catch {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET locks threw an error: $($_.Exception.Message)"
            & $recordStep 'Preflight-Locks' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        $locksCode = [int](Get-ObjectPropertyValue -InputObject $locksResp -PropertyName 'StatusCode')
        if ($locksCode -ne 200) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET locks returned HTTP $locksCode."
            & $recordStep 'Preflight-Locks' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        $locksBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $locksResp -PropertyName 'Content')
        if (-not (Test-HasJsonValueArray -InputObject $locksBody)) {
            Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET locks returned an invalid JSON body or missing 'value' array."
            & $recordStep 'Preflight-Locks' 'Failed'
            $exitCode = 1
            return $exitCode
        }
        $locksList = @(Get-ObjectPropertyValue -InputObject $locksBody -PropertyName 'value')
        foreach ($lock in $locksList) {
            if ($null -eq $lock) { continue }
            $lockName = "$(Get-ObjectPropertyValue -InputObject $lock -PropertyName 'name')"
            $lockProps = Get-ObjectPropertyValue -InputObject $lock -PropertyName 'properties'
            $lockLevel = "$(Get-ObjectPropertyValue -InputObject $lockProps -PropertyName 'level')"
            if ($lockLevel -ieq 'ReadOnly') {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Resource has a ReadOnly lock '$lockName'. Remove the ReadOnly lock before repairing identity."
                & $recordStep 'Preflight-Locks' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            if ($lockLevel -ieq 'CanNotDelete') {
                Write-RepairLog -Message "Found CanNotDelete lock '$lockName' on cluster resource (does not block PATCH operations)."
            }
        }
        & $recordStep 'Preflight-Locks' 'Succeeded'

        # 8. Role assignments of the old principal (only when stripping; bounded nextLink pagination)
        if ($ResumeFrom -eq 'Start') {
            $roleAssignmentsFile = Join-Path -Path $runDir -ChildPath 'role-assignments-before.json'
            $roleAssignmentsList = New-Object System.Collections.ArrayList
            if (-not [string]::IsNullOrWhiteSpace($oldPrincipalId)) {
                $raPath = "/subscriptions/$($cfg.subscriptionId)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$oldPrincipalId'"
                $nextLink = $null
                $maxRaPages = 100
                $pageCount = 0

                while ($true) {
                    $pageCount++
                    if ($pageCount -gt $maxRaPages) {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: Role assignment pagination exceeded $maxRaPages pages."
                        & $recordStep 'Preflight-RoleAssignments' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }

                    $raResp = $null
                    try {
                        if ($pageCount -eq 1) {
                            $raResp = Invoke-ArmRestRequest -Path $raPath -Method GET
                        } else {
                            $raResp = Invoke-ArmRestRequest -Uri $nextLink -Method GET
                        }
                    } catch {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET role assignments threw an error: $($_.Exception.Message)"
                        & $recordStep 'Preflight-RoleAssignments' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }

                    $raCode = [int](Get-ObjectPropertyValue -InputObject $raResp -PropertyName 'StatusCode')
                    if ($raCode -ne 200) {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET role assignments for principal '$oldPrincipalId' returned HTTP $raCode."
                        & $recordStep 'Preflight-RoleAssignments' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }

                    $raBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $raResp -PropertyName 'Content')
                    if (-not (Test-HasJsonValueArray -InputObject $raBody)) {
                        Write-RepairLog -Level ERROR -Message "Pre-flight failed: GET role assignments returned an invalid JSON body or missing 'value' array."
                        & $recordStep 'Preflight-RoleAssignments' 'Failed'
                        $exitCode = 1
                        return $exitCode
                    }

                    $raPageItems = @(Get-ObjectPropertyValue -InputObject $raBody -PropertyName 'value')
                    foreach ($item in $raPageItems) {
                        if ($null -ne $item) {
                            [void]$roleAssignmentsList.Add($item)
                        }
                    }

                    $nextLink = "$(Get-ObjectPropertyValue -InputObject $raBody -PropertyName 'nextLink')".Trim()
                    if ([string]::IsNullOrWhiteSpace($nextLink)) {
                        break
                    }
                }
            }

            try {
                $WhatIfPreference = $false
                $ConfirmPreference = 'None'
                [ordered]@{
                    capturedUtc     = (Get-UtcTimestamp)
                    oldPrincipalId  = $oldPrincipalId
                    roleAssignments = $roleAssignmentsList.ToArray()
                } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $roleAssignmentsFile -Encoding UTF8
            } finally {
                $WhatIfPreference = $savedWhatIf
                $ConfirmPreference = $savedConfirm
            }

            if ($roleAssignmentsList.Count -gt 0 -and -not $AcceptRoleAssignmentLoss.IsPresent) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Old principal '$oldPrincipalId' has $($roleAssignmentsList.Count) role assignment(s) exported to '$roleAssignmentsFile'. Re-run with -AcceptRoleAssignmentLoss after planning their recreation."
                & $recordStep 'Preflight-RoleAssignments' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            & $recordStep 'Preflight-RoleAssignments' 'Succeeded'
        } else {
            & $recordStep 'Preflight-RoleAssignments' 'Skipped'
        }

        if ($ResumeFrom -eq 'AssignIdentity' -and $oldIdentityType -ieq 'SystemAssigned' -and -not [string]::IsNullOrWhiteSpace($presentPrincipalId)) {
            $summaryState = Get-PreviousStripSummaryState -LogDirectory $cfg.logDirectory
            foreach ($priorOldPid in @($summaryState.AllOldPrincipalIds)) {
                if ($presentPrincipalId -ieq $priorOldPid) {
                    Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster still has an old identity ('$presentPrincipalId') recorded in an earlier summary.json; the old identity was never removed: run again without -ResumeFrom."
                    & $recordStep 'Preflight-ResumeIdentity' 'Failed'
                    $exitCode = 1
                    return $exitCode
                }
            }
            $knownOldPid = $PreviousPrincipalId
            if ([string]::IsNullOrWhiteSpace($knownOldPid)) {
                $knownOldPid = $summaryState.LatestSucceededOldPrincipal
            }
            if ([string]::IsNullOrWhiteSpace($knownOldPid)) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: -ResumeFrom AssignIdentity found an existing SystemAssigned identity ('$presentPrincipalId'), but the previous principal ID is unknown. Supply -PreviousPrincipalId <guid> to verify whether the old identity was replaced."
                & $recordStep 'Preflight-ResumeIdentity' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            if ($presentPrincipalId -ieq $knownOldPid) {
                Write-RepairLog -Level ERROR -Message "Pre-flight failed: Cluster still has the old identity ('$presentPrincipalId'); the old identity was never removed: run again without -ResumeFrom."
                & $recordStep 'Preflight-ResumeIdentity' 'Failed'
                $exitCode = 1
                return $exitCode
            }
            $oldPrincipalId = $knownOldPid
            $newPrincipalId = $presentPrincipalId
            & $recordStep 'Preflight-ResumeIdentity' 'Succeeded'
        }

        # Show execution plan
        Write-RepairLog -Message ("Plan: Target='{0}' | Location='{1}' | CurrentIdentityType='{2}' | OldPrincipalId='{3}' | ResumeFrom='{4}'" -f `
            $expectedResourceId, $resourceLocation, $(if ($oldIdentityType) { $oldIdentityType } else { 'None' }), $(if ($oldPrincipalId) { $oldPrincipalId } else { '<none>' }), $ResumeFrom)

        $stageOrder = @{
            Start              = 0
            AssignIdentity     = 1
            RepairRegistration = 2
            Verify             = 3
        }
        $startRank = $stageOrder[$ResumeFrom]

        # Steps A & B: Replace or assign cluster managed identity (covered by ONE ShouldProcess confirmation)
        $needStrip = ($startRank -le 0)
        $needAssign = ($startRank -le 1) -and -not ($ResumeFrom -eq 'AssignIdentity' -and -not [string]::IsNullOrWhiteSpace($newPrincipalId))
        if (-not $needStrip) {
            & $recordStep 'StripIdentity' 'Skipped'
        }
        if ($startRank -gt 1) {
            & $recordStep 'AssignIdentity' 'Skipped'
        } elseif (-not $needAssign) {
            Write-RepairLog -Message "ResumeFrom=AssignIdentity: Cluster already has a new SystemAssigned identity (principalId='$newPrincipalId') different from '$oldPrincipalId'. Skipping PATCH and continuing to registration repair."
            & $recordStep 'AssignIdentity' 'ReconciledExisting'
            $currentStage = 'Repair'
        }

        if ($needStrip -or $needAssign) {
            $identityActionDesc = if ($needStrip) {
                "Replace cluster managed identity (PATCH identity.type = 'None' then 'SystemAssigned'; removes principal '$oldPrincipalId')"
            } else {
                "Assign cluster managed identity (PATCH identity.type = 'SystemAssigned')"
            }
            $shouldReplaceIdentity = $PSCmdlet.ShouldProcess($expectedResourceId, $identityActionDesc)
            if (-not $shouldReplaceIdentity) {
                if ($WhatIfPreference) {
                    Write-RepairLog -Message "What if: $identityActionDesc on '$expectedResourceId'."
                    if ($needStrip) { & $recordStep 'StripIdentity' 'WhatIf' }
                    if ($needAssign) { & $recordStep 'AssignIdentity' 'WhatIf' }
                } else {
                    if ($needStrip) {
                        Write-RepairLog -Level WARN -Message "Operator declined confirmation before replacing cluster identity; nothing was changed."
                        & $recordStep 'StripIdentity' 'Declined'
                    } else {
                        Write-RepairLog -Level WARN -Message "Operator declined confirmation before assigning SystemAssigned identity. Resume with: $resumeAssignCmd"
                        & $recordStep 'AssignIdentity' 'Declined'
                    }
                    $exitCode = 2
                    return $exitCode
                }
            } else {
                # Stale-plan check: re-read the cluster resource once right after confirmation before any PATCH.
                $recheckResp = $null
                try {
                    $recheckResp = Invoke-ArmRestRequest -Path $clusterPath -Method GET
                } catch {
                    Write-RepairLog -Level ERROR -Message "Pre-write re-check GET cluster resource threw an error ($($_.Exception.Message)); aborting before any write."
                    & $recordStep 'PreWrite-Recheck' 'Failed'
                    $exitCode = 1
                    return $exitCode
                }
                $recheckCode = [int](Get-ObjectPropertyValue -InputObject $recheckResp -PropertyName 'StatusCode')
                $recheckBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $recheckResp -PropertyName 'Content')
                $recheckResId = "$(Get-ObjectPropertyValue -InputObject $recheckBody -PropertyName 'id')"
                if ($recheckCode -ne 200 -or $null -eq $recheckBody -or [string]::IsNullOrWhiteSpace($recheckResId)) {
                    Write-RepairLog -Level ERROR -Message "Pre-write re-check GET cluster resource returned HTTP $recheckCode or an invalid body; aborting before any write."
                    & $recordStep 'PreWrite-Recheck' 'Failed'
                    $exitCode = 1
                    return $exitCode
                }
                $recheckIdObj = Get-ObjectPropertyValue -InputObject $recheckBody -PropertyName 'identity'
                $recheckType = "$(Get-ObjectPropertyValue -InputObject $recheckIdObj -PropertyName 'type')"
                $recheckPidRaw = Get-ObjectPropertyValue -InputObject $recheckIdObj -PropertyName 'principalId'
                $recheckPid = if ($null -ne $recheckPidRaw -and -not [string]::IsNullOrWhiteSpace("$recheckPidRaw")) { "$recheckPidRaw".Trim() } else { $null }
                $expectedPid = if (-not [string]::IsNullOrWhiteSpace($presentPrincipalId)) { $presentPrincipalId } else { $null }
                if ($recheckType -ine $oldIdentityType -or "$recheckPid" -ine "$expectedPid") {
                    Write-RepairLog -Level ERROR -Message "Cluster identity state changed since pre-flight (planned type='$oldIdentityType' principalId='$expectedPid', current type='$recheckType' principalId='$recheckPid'); aborting with no write. Re-run the script."
                    & $recordStep 'PreWrite-Recheck' 'Failed'
                    $exitCode = 1
                    return $exitCode
                }
                & $recordStep 'PreWrite-Recheck' 'Succeeded'

                if ($needStrip) {
                    $currentStage = 'Strip'
                    Write-RepairLog -Message "Step 1/4: Removing existing cluster managed identity (identity.type = 'None')..."
                    $stripBudget = @{
                        StartedUtc     = (Get-Date).ToUniversalTime()
                        TimeoutSeconds = $cfg.identityTimeoutSeconds
                        WaitedSeconds  = 0
                    }
                    try {
                        $stripPayload = (@{ identity = @{ type = 'None' } } | ConvertTo-Json -Compress)
                        $stripResp = Invoke-ArmRestRequest -Path $clusterPath -Method PATCH -Payload $stripPayload
                        $stripCode = [int](Get-ObjectPropertyValue -InputObject $stripResp -PropertyName 'StatusCode')
                        if ($stripCode -notin @(200, 201, 202)) {
                            Write-RepairLog -Level ERROR -Message "Removing cluster identity failed or outcome is unknown: PATCH returned HTTP $stripCode."
                            Show-ClusterIdentityState -ClusterPath $clusterPath
                            & $recordStep 'StripIdentity' 'Failed'
                            $exitCode = 3
                            return $exitCode
                        }

                        if ($stripCode -eq 202) {
                            $stripHeaders = Get-ObjectPropertyValue -InputObject $stripResp -PropertyName 'Headers'
                            $initialStripWait = Get-RetryAfterSecond -Headers $stripHeaders -DefaultSeconds 0
                            $asyncUrl = Get-ResponseHeaderValue -Headers $stripHeaders -HeaderName 'Azure-AsyncOperation'
                            $asyncProto = 'AzureAsyncOperation'
                            if ([string]::IsNullOrWhiteSpace($asyncUrl)) {
                                $asyncUrl = Get-ResponseHeaderValue -Headers $stripHeaders -HeaderName 'Location'
                                $asyncProto = 'Location'
                            }
                            if (-not [string]::IsNullOrWhiteSpace($asyncUrl)) {
                                Write-RepairLog -Message "Waiting for async strip operation ($asyncProto) to complete ($asyncUrl)..."
                                $asyncOk = Wait-ArmAsyncOperation -OperationUri $asyncUrl -Protocol $asyncProto -PollIntervalSeconds $cfg.pollIntervalSeconds -TimeoutSeconds $cfg.identityTimeoutSeconds -InitialWaitSeconds $initialStripWait -Budget $stripBudget
                                if (-not $asyncOk) {
                                    Write-RepairLog -Level ERROR -Message "Async strip operation failed or timed out; removal outcome is unknown."
                                    Show-ClusterIdentityState -ClusterPath $clusterPath
                                    & $recordStep 'StripIdentity' 'Failed'
                                    $exitCode = 3
                                    return $exitCode
                                }
                            } elseif ($initialStripWait -gt 0) {
                                if (-not (Invoke-BudgetedWait -Budget $stripBudget -RequestedSeconds $initialStripWait)) {
                                    Write-RepairLog -Level ERROR -Message "Timed out waiting for initial strip 202 Retry-After delay; removal outcome is unknown."
                                    Show-ClusterIdentityState -ClusterPath $clusterPath
                                    & $recordStep 'StripIdentity' 'Failed'
                                    $exitCode = 3
                                    return $exitCode
                                }
                            }
                        }

                        $maxPolls = [Math]::Max(1, [int][Math]::Ceiling($cfg.identityTimeoutSeconds / [double]$cfg.pollIntervalSeconds) + 2)
                        $identityGone = $false
                        for ($p = 1; $p -le $maxPolls; $p++) {
                            if (-not (Test-BudgetActive -Budget $stripBudget)) {
                                break
                            }
                            $pollResp = $null
                            $sleepSec = $cfg.pollIntervalSeconds
                            try {
                                $pollResp = Invoke-ArmRestRequest -Path $clusterPath -Method GET
                            } catch {
                                Write-RepairLog -Level WARN -Message "GET cluster resource during strip polling threw a transport error ($($_.Exception.Message)); retrying..."
                                if ($p -lt $maxPolls -and (Invoke-BudgetedWait -Budget $stripBudget -RequestedSeconds $sleepSec)) {
                                    continue
                                }
                                break
                            }

                            if (-not (Test-BudgetActive -Budget $stripBudget)) {
                                break
                            }

                            $pollCode = [int](Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'StatusCode')
                            $pollHeaders = Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'Headers'
                            $sleepSec = Get-RetryAfterSecond -Headers $pollHeaders -DefaultSeconds $cfg.pollIntervalSeconds

                            if ($pollCode -eq 200) {
                                $pollBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'Content')
                                $pollResId = "$(Get-ObjectPropertyValue -InputObject $pollBody -PropertyName 'id')"
                                if ($null -ne $pollBody -and -not [string]::IsNullOrWhiteSpace($pollResId)) {
                                    $pollIdObj = Get-ObjectPropertyValue -InputObject $pollBody -PropertyName 'identity'
                                    if ($null -eq $pollIdObj) {
                                        $identityGone = $true
                                        break
                                    }
                                    $pollIdType = "$(Get-ObjectPropertyValue -InputObject $pollIdObj -PropertyName 'type')"
                                    if ($pollIdType -ieq 'None') {
                                        $identityGone = $true
                                        break
                                    }
                                }
                            }

                            if (-not ($p -lt $maxPolls -and (Invoke-BudgetedWait -Budget $stripBudget -RequestedSeconds $sleepSec))) {
                                break
                            }
                        }

                        if (-not $identityGone) {
                            Write-RepairLog -Level ERROR -Message "Timed out or failed waiting for verified cluster identity removal within $($cfg.identityTimeoutSeconds) seconds; removal outcome is unknown."
                            Show-ClusterIdentityState -ClusterPath $clusterPath
                            & $recordStep 'StripIdentity' 'Failed'
                            $exitCode = 3
                            return $exitCode
                        }
                        Write-RepairLog -Message "Cluster managed identity successfully removed."
                        & $recordStep 'StripIdentity' 'Succeeded'
                        $currentStage = 'Assign'
                    } catch {
                        Write-RepairLog -Level ERROR -Message "Removing cluster identity threw an exception ($($_.Exception.Message)); removal outcome is unknown."
                        Show-ClusterIdentityState -ClusterPath $clusterPath
                        & $recordStep 'StripIdentity' 'Failed'
                        $exitCode = 3
                        return $exitCode
                    }
                }

                if ($needAssign) {
                    $currentStage = 'Assign'
                    Write-RepairLog -Message "Step 2/4: Assigning new SystemAssigned managed identity..."
                    $assignBudget = @{
                        StartedUtc     = (Get-Date).ToUniversalTime()
                        TimeoutSeconds = $cfg.identityTimeoutSeconds
                        WaitedSeconds  = 0
                    }
                    try {
                        $assignPayload = (@{ identity = @{ type = 'SystemAssigned' } } | ConvertTo-Json -Compress)
                        $assignResp = Invoke-ArmRestRequest -Path $clusterPath -Method PATCH -Payload $assignPayload
                        $assignCode = [int](Get-ObjectPropertyValue -InputObject $assignResp -PropertyName 'StatusCode')
                        if ($assignCode -notin @(200, 201, 202)) {
                            Write-RepairLog -Level ERROR -Message "Assigning new SystemAssigned identity failed (HTTP $assignCode). The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                            & $recordStep 'AssignIdentity' 'Failed'
                            $exitCode = 4
                            return $exitCode
                        }

                        if ($assignCode -eq 202) {
                            $assignHeaders = Get-ObjectPropertyValue -InputObject $assignResp -PropertyName 'Headers'
                            $initialAssignWait = Get-RetryAfterSecond -Headers $assignHeaders -DefaultSeconds 0
                            $asyncUrl = Get-ResponseHeaderValue -Headers $assignHeaders -HeaderName 'Azure-AsyncOperation'
                            $asyncProto = 'AzureAsyncOperation'
                            if ([string]::IsNullOrWhiteSpace($asyncUrl)) {
                                $asyncUrl = Get-ResponseHeaderValue -Headers $assignHeaders -HeaderName 'Location'
                                $asyncProto = 'Location'
                            }
                            if (-not [string]::IsNullOrWhiteSpace($asyncUrl)) {
                                Write-RepairLog -Message "Waiting for async assign operation ($asyncProto) to complete ($asyncUrl)..."
                                $asyncOk = Wait-ArmAsyncOperation -OperationUri $asyncUrl -Protocol $asyncProto -PollIntervalSeconds $cfg.pollIntervalSeconds -TimeoutSeconds $cfg.identityTimeoutSeconds -InitialWaitSeconds $initialAssignWait -Budget $assignBudget
                                if (-not $asyncOk) {
                                    Write-RepairLog -Level ERROR -Message "Async assign operation failed. The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                                    & $recordStep 'AssignIdentity' 'Failed'
                                    $exitCode = 4
                                    return $exitCode
                                }
                            } elseif ($initialAssignWait -gt 0) {
                                if (-not (Invoke-BudgetedWait -Budget $assignBudget -RequestedSeconds $initialAssignWait)) {
                                    Write-RepairLog -Level ERROR -Message "Timed out waiting for initial assign 202 Retry-After delay. The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                                    & $recordStep 'AssignIdentity' 'Failed'
                                    $exitCode = 4
                                    return $exitCode
                                }
                            }
                        }

                        $maxPolls = [Math]::Max(1, [int][Math]::Ceiling($cfg.identityTimeoutSeconds / [double]$cfg.pollIntervalSeconds) + 2)
                        $identityAssigned = $false
                        for ($p = 1; $p -le $maxPolls; $p++) {
                            if (-not (Test-BudgetActive -Budget $assignBudget)) {
                                break
                            }
                            $pollResp = $null
                            $sleepSec = $cfg.pollIntervalSeconds
                            try {
                                $pollResp = Invoke-ArmRestRequest -Path $clusterPath -Method GET
                            } catch {
                                Write-RepairLog -Level WARN -Message "GET cluster resource during assign polling threw a transport error ($($_.Exception.Message)); retrying..."
                                if ($p -lt $maxPolls -and (Invoke-BudgetedWait -Budget $assignBudget -RequestedSeconds $sleepSec)) {
                                    continue
                                }
                                break
                            }

                            if (-not (Test-BudgetActive -Budget $assignBudget)) {
                                break
                            }

                            $pollCode = [int](Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'StatusCode')
                            $pollHeaders = Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'Headers'
                            $sleepSec = Get-RetryAfterSecond -Headers $pollHeaders -DefaultSeconds $cfg.pollIntervalSeconds

                            if ($pollCode -eq 200) {
                                $pollBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $pollResp -PropertyName 'Content')
                                $pollResId = "$(Get-ObjectPropertyValue -InputObject $pollBody -PropertyName 'id')"
                                if ($null -ne $pollBody -and -not [string]::IsNullOrWhiteSpace($pollResId)) {
                                    $pollIdObj = Get-ObjectPropertyValue -InputObject $pollBody -PropertyName 'identity'
                                    $pollIdType = "$(Get-ObjectPropertyValue -InputObject $pollIdObj -PropertyName 'type')"
                                    $pollPid = "$(Get-ObjectPropertyValue -InputObject $pollIdObj -PropertyName 'principalId')".Trim()
                                    if ($pollIdType -ieq 'SystemAssigned' -and -not [string]::IsNullOrWhiteSpace($pollPid) -and ([string]::IsNullOrWhiteSpace($oldPrincipalId) -or $pollPid -ine $oldPrincipalId)) {
                                        $newPrincipalId = $pollPid
                                        $identityAssigned = $true
                                        break
                                    }
                                }
                            }

                            if (-not ($p -lt $maxPolls -and (Invoke-BudgetedWait -Budget $assignBudget -RequestedSeconds $sleepSec))) {
                                break
                            }
                        }

                        if (-not $identityAssigned) {
                            Write-RepairLog -Level ERROR -Message "Timed out waiting for a new SystemAssigned principalId within $($cfg.identityTimeoutSeconds) seconds. The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                            & $recordStep 'AssignIdentity' 'Failed'
                            $exitCode = 4
                            return $exitCode
                        }

                        Write-RepairLog -Message "New SystemAssigned identity provisioned (principalId='$newPrincipalId'). Waiting $($cfg.propagationWaitSeconds) seconds for Entra replication..."
                        if ($cfg.propagationWaitSeconds -gt 0) {
                            $null = Start-Sleep -Seconds $cfg.propagationWaitSeconds
                        }
                        & $recordStep 'AssignIdentity' 'Succeeded'
                        $currentStage = 'Repair'
                    } catch {
                        Write-RepairLog -Level ERROR -Message "Assigning new SystemAssigned identity threw an exception ($($_.Exception.Message)). The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                        & $recordStep 'AssignIdentity' 'Failed'
                        $exitCode = 4
                        return $exitCode
                    }
                }
            }
        }

        # Step C: Repair registration (when ResumeFrom is Start, AssignIdentity, or RepairRegistration)
        if ($startRank -le 2) {
            $shouldRepair = $PSCmdlet.ShouldProcess($cfg.clusterName, "Register-AzStackHCI -RepairRegistration")
            if (-not $shouldRepair) {
                if ($WhatIfPreference) {
                    Write-RepairLog -Message "What if: Register-AzStackHCI -RepairRegistration on '$($cfg.clusterName)'."
                    & $recordStep 'RepairRegistration' 'WhatIf'
                } else {
                    $replacedNote = if ($needStrip -or $needAssign) { "The cluster identity has already been replaced (newPrincipalId='$newPrincipalId'). " } else { '' }
                    Write-RepairLog -Level WARN -Message ("{0}Operator declined confirmation before Register-AzStackHCI -RepairRegistration. Resume with: {1}" -f $replacedNote, $resumeRepairCmd)
                    & $recordStep 'RepairRegistration' 'Declined'
                    $exitCode = 2
                    return $exitCode
                }
            } else {
                $currentStage = 'Repair'
                Write-RepairLog -Message "Step 3/4: Running Register-AzStackHCI -RepairRegistration on local cluster node..."
                $regResultObj = $null
                try {
                    $regResultObj = Register-AzStackHCI `
                        -SubscriptionId $cfg.subscriptionId `
                        -TenantId $cfg.tenantId `
                        -Region $cfg.region `
                        -ResourceGroupName $cfg.resourceGroupName `
                        -ResourceName $cfg.clusterName `
                        -RepairRegistration `
                        -UseDeviceAuthentication
                } catch {
                    Write-RepairLog -Level ERROR -Message "Register-AzStackHCI -RepairRegistration threw an exception: $($_.Exception.Message). Resume with: $resumeRepairCmd"
                    & $recordStep 'RepairRegistration' 'Failed'
                    $exitCode = 5
                    return $exitCode
                }

                $regSucceeded = $false
                $directResult = "$(Get-ObjectPropertyValue -InputObject $regResultObj -PropertyName 'Result')".Trim()
                if (-not [string]::IsNullOrWhiteSpace($directResult)) {
                    $regSucceeded = ($directResult -ieq 'Success')
                } else {
                    $renderedReg = [regex]::Replace(($regResultObj | Out-String), '\x1B\[[0-?]*[ -/]*[@-~]', '')
                    $resultMatches = [regex]::Matches($renderedReg, '(?im)^\s*Result\s*:\s*(\S+)\s*$')
                    if ($resultMatches.Count -eq 1 -and $resultMatches[0].Groups[1].Value -ieq 'Success') {
                        $regSucceeded = $true
                    }
                }

                if (-not $regSucceeded) {
                    Write-RepairLog -Level ERROR -Message "Register-AzStackHCI -RepairRegistration did not report Result : Success. Resume with: $resumeRepairCmd"
                    & $recordStep 'RepairRegistration' 'Failed'
                    $exitCode = 5
                    return $exitCode
                }
                Write-RepairLog -Message "Register-AzStackHCI -RepairRegistration succeeded."
                & $recordStep 'RepairRegistration' 'Succeeded'
                $currentStage = 'Verify'
            }
        } else {
            & $recordStep 'RepairRegistration' 'Skipped'
        }

        # Step D: Sync and verify
        $shouldVerify = $PSCmdlet.ShouldProcess($cfg.clusterName, "Sync-AzureStackHCI and verify ConnectionStatus")
        if (-not $shouldVerify) {
            if ($WhatIfPreference) {
                Write-RepairLog -Message "What if: Sync-AzureStackHCI and verify ConnectionStatus on '$($cfg.clusterName)'."
                & $recordStep 'VerifySync' 'WhatIf'
                $exitCode = 0
                return $exitCode
            } else {
                Write-RepairLog -Level WARN -Message "Operator declined confirmation before Sync-AzureStackHCI. Resume with: $resumeVerifyCmd"
                & $recordStep 'VerifySync' 'Declined'
                $exitCode = 2
                return $exitCode
            }
        }

        $currentStage = 'Verify'
        Write-RepairLog -Message "Step 4/4: Running Sync-AzureStackHCI and watching connection status for up to $($cfg.syncWatchMinutes) minute(s)..."
        try {
            $null = Sync-AzureStackHCI
        } catch {
            Write-RepairLog -Level ERROR -Message "Sync-AzureStackHCI threw an error: $($_.Exception.Message). Resume with: $resumeVerifyCmd"
            & $recordStep 'VerifySync' 'Failed'
            $exitCode = 6
            return $exitCode
        }

        $watchSeconds = $cfg.syncWatchMinutes * 60
        $syncBudget = @{
            StartedUtc     = (Get-Date).ToUniversalTime()
            TimeoutSeconds = $watchSeconds
            WaitedSeconds  = 0
        }
        $maxSyncPolls = [Math]::Max(1, [int][Math]::Ceiling($watchSeconds / [double]$cfg.pollIntervalSeconds) + 2)
        $connected = $false
        $hciAfter = $null

        for ($s = 1; $s -le $maxSyncPolls; $s++) {
            if (-not (Test-BudgetActive -Budget $syncBudget)) {
                break
            }
            try {
                $hciAfter = Get-AzureStackHCI
            } catch {
                Write-RepairLog -Level WARN -Message "Get-AzureStackHCI during sync watch threw an error ($($_.Exception.Message)); retrying..."
                if ($s -lt $maxSyncPolls -and (Invoke-BudgetedWait -Budget $syncBudget -RequestedSeconds $cfg.pollIntervalSeconds)) {
                    continue
                }
                break
            }

            if (-not (Test-BudgetActive -Budget $syncBudget)) {
                break
            }

            $connStatus = "$(Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'ConnectionStatus')"
            $rawAfterLastConn = Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'LastConnected'
            $afterLastConnUtc = $null
            if ($null -ne $rawAfterLastConn -and "$rawAfterLastConn" -ne '') {
                $afterLastConnUtc = ([datetime]$rawAfterLastConn).ToUniversalTime()
            }

            $isNewer = ($null -ne $afterLastConnUtc) -and ($null -eq $beforeLastConnectedUtc -or $afterLastConnUtc -gt $beforeLastConnectedUtc)
            if ($connStatus -ieq 'Connected' -and $isNewer) {
                $connected = $true
                break
            }

            if (-not ($s -lt $maxSyncPolls -and (Invoke-BudgetedWait -Budget $syncBudget -RequestedSeconds $cfg.pollIntervalSeconds))) {
                break
            }
        }

        # Best-effort post-repair evidence read (Register-AzStackHCI 2.x calls Disconnect-AzAccount in finally; do not start a new sign-in).
        try {
            $postCtx = $null
            try {
                $postCtx = Get-AzContext
            } catch {
                $postCtx = $null
            }
            $postTenant = $null
            $postSub = $null
            if ($null -ne $postCtx) {
                $postTenantObj = Get-ObjectPropertyValue -InputObject $postCtx -PropertyName 'Tenant'
                $postSubObj = Get-ObjectPropertyValue -InputObject $postCtx -PropertyName 'Subscription'
                $postTenant = "$(Get-ObjectPropertyValue -InputObject $postTenantObj -PropertyName 'Id')"
                $postSub = "$(Get-ObjectPropertyValue -InputObject $postSubObj -PropertyName 'Id')"
            }
            if ($null -ne $postCtx -and $postTenant -ieq $cfg.tenantId -and $postSub -ieq $cfg.subscriptionId) {
                $afterClusterResp = Invoke-ArmRestRequest -Path $clusterPath -Method GET
                $afterClusterCode = [int](Get-ObjectPropertyValue -InputObject $afterClusterResp -PropertyName 'StatusCode')
                $afterClusterBody = ConvertFrom-JsonSafe -Content (Get-ObjectPropertyValue -InputObject $afterClusterResp -PropertyName 'Content')
                $afterClusterResId = "$(Get-ObjectPropertyValue -InputObject $afterClusterBody -PropertyName 'id')"
                $validAfterCluster = ($afterClusterCode -eq 200 -and $null -ne $afterClusterBody -and -not [string]::IsNullOrWhiteSpace($afterClusterResId))
                if (-not $validAfterCluster) {
                    Write-RepairLog -Level WARN -Message "Post-repair evidence read (after.json) failed: GET cluster resource returned HTTP $afterClusterCode or an invalid resource body; continuing."
                }
                $afterSnapshot = [ordered]@{
                    capturedUtc       = (Get-UtcTimestamp)
                    clusterResource   = if ($validAfterCluster) { $afterClusterBody } else { $null }
                    localRegistration = if ($null -ne $hciAfter) {
                        [ordered]@{
                            AzureResourceUri   = "$(Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'AzureResourceUri')"
                            RegistrationStatus = "$(Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'RegistrationStatus')"
                            ConnectionStatus   = "$(Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'ConnectionStatus')"
                            LastConnected      = "$(Get-ObjectPropertyValue -InputObject $hciAfter -PropertyName 'LastConnected')"
                        }
                    } else { $null }
                }
                try {
                    $WhatIfPreference = $false
                    $ConfirmPreference = 'None'
                    $afterSnapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $runDir -ChildPath 'after.json') -Encoding UTF8
                } finally {
                    $WhatIfPreference = $savedWhatIf
                    $ConfirmPreference = $savedConfirm
                }
            } else {
                Write-RepairLog -Message "Azure session was disconnected by Register-AzStackHCI; skipping post-repair ARM evidence read (after.json) to avoid another interactive sign-in."
            }
        } catch {
            Write-RepairLog -Level WARN -Message "Post-repair evidence read (after.json) failed: $($_.Exception.Message)"
        }

        if (-not $connected) {
            Write-RepairLog -Level ERROR -Message "Cluster did not report Connected with a newer LastConnected timestamp within $($cfg.syncWatchMinutes) minute(s). Resume with: $resumeVerifyCmd"
            & $recordStep 'VerifySync' 'Failed'
            $exitCode = 6
            return $exitCode
        }

        Write-RepairLog -Message "Cluster is Connected with an updated LastConnected timestamp. Identity repair complete."
        & $recordStep 'VerifySync' 'Succeeded'
        $exitCode = 0
        return $exitCode
    } catch {
        $errMsg = $_.Exception.Message
        switch ($currentStage) {
            'Strip' {
                Write-RepairLog -Level ERROR -Message "Unexpected error during identity removal (Strip): $errMsg"
                Show-ClusterIdentityState -ClusterPath $clusterPath
                & $recordStep 'StripIdentity' 'Failed'
                $exitCode = 3
            }
            'Assign' {
                Write-RepairLog -Level ERROR -Message "Unexpected error during identity assignment (Assign): $errMsg. The cluster may currently have NO identity. Resume with: $resumeAssignCmd"
                & $recordStep 'AssignIdentity' 'Failed'
                $exitCode = 4
            }
            'Repair' {
                Write-RepairLog -Level ERROR -Message "Unexpected error during registration repair (Repair): $errMsg. Resume with: $resumeRepairCmd"
                & $recordStep 'RepairRegistration' 'Failed'
                $exitCode = 5
            }
            'Verify' {
                Write-RepairLog -Level ERROR -Message "Unexpected error during synchronization verification (Verify): $errMsg. Resume with: $resumeVerifyCmd"
                & $recordStep 'VerifySync' 'Failed'
                $exitCode = 6
            }
            default {
                Write-RepairLog -Level ERROR -Message "Unexpected error during pre-flight: $errMsg"
                & $recordStep 'Preflight' 'Failed'
                $exitCode = 1
            }
        }
        return $exitCode
    } finally {
        $interrupted = $false
        if ($exitCode -lt 0) {
            $interrupted = $true
            switch ($currentStage) {
                'Strip' {
                    $exitCode = 3
                    Write-RepairLog -Level ERROR -Message "Execution was interrupted during identity removal (Strip). Current identity state in Azure is unknown; inspect the cluster resource before resuming."
                }
                'Assign' {
                    $exitCode = 4
                    Write-RepairLog -Level ERROR -Message "Execution was interrupted during identity assignment (Assign). The cluster may have NO identity. Resume with: $resumeAssignCmd"
                }
                'Repair' {
                    $exitCode = 5
                    Write-RepairLog -Level ERROR -Message "Execution was interrupted during registration repair (Repair). Resume with: $resumeRepairCmd"
                }
                'Verify' {
                    $exitCode = 6
                    Write-RepairLog -Level ERROR -Message "Execution was interrupted during synchronization verification (Verify). Resume with: $resumeVerifyCmd"
                }
                default {
                    $exitCode = 1
                    Write-RepairLog -Level WARN -Message "Execution was interrupted before any write step completed; nothing was changed."
                }
            }
        }

        $summary = [ordered]@{
            startedUtc     = $startedUtc
            endedUtc       = (Get-UtcTimestamp)
            exitCode       = $exitCode
            interrupted    = $interrupted
            transcript     = $transcriptStarted
            resumeFrom     = $ResumeFrom
            oldPrincipalId = $oldPrincipalId
            newPrincipalId = $newPrincipalId
            steps          = $steps.ToArray()
        }
        try {
            $WhatIfPreference = $false
            $ConfirmPreference = 'None'
            $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $runDir -ChildPath 'summary.json') -Encoding UTF8
        } catch {
            Write-Verbose "Failed to write summary.json: $($_.Exception.Message)"
        } finally {
            $WhatIfPreference = $savedWhatIf
            $ConfirmPreference = $savedConfirm
        }
        if ($transcriptStarted) {
            try {
                $WhatIfPreference = $false
                $ConfirmPreference = 'None'
                $null = Stop-Transcript
            } catch {
                Write-Verbose "Stop-Transcript failed: $($_.Exception.Message)"
            } finally {
                $WhatIfPreference = $savedWhatIf
                $ConfirmPreference = $savedConfirm
            }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $PSBoundParameters.ContainsKey('ConfigPath')) {
        $PSBoundParameters['ConfigPath'] = $ConfigPath
    }
    if (-not [string]::IsNullOrWhiteSpace($PreviousPrincipalId) -and -not $PSBoundParameters.ContainsKey('PreviousPrincipalId')) {
        $PSBoundParameters['PreviousPrincipalId'] = $PreviousPrincipalId
    }
    exit (Invoke-ClusterIdentityRepair @PSBoundParameters)
}
