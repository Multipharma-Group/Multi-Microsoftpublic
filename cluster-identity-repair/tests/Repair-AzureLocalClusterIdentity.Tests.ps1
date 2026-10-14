# Dispatcher-authored acceptance tests (2026-10-14). Do not edit to make an implementation pass.
# Run: pwsh -NoProfile -Command "Invoke-Pester -Path scripts/cluster-identity-repair/tests -Output Detailed -CI"
# Also run under Windows PowerShell 5.1 (Pester 5) on a Windows runner.
# 2026-10-14: BeforeEach moved into an outer Describe (Pester 5 rejects it at the file root; found by the implementer).

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:ScriptPath = Join-Path $script:Root 'Repair-AzureLocalClusterIdentity.ps1'

    # Stubs for cmdlets that do not exist off-node; every test mocks them.
    function global:Invoke-AzRestMethod { [CmdletBinding()] param($Path, $Uri, $Method, $Payload) }
    function global:Get-AzureStackHCI { [CmdletBinding()] param() }
    function global:Sync-AzureStackHCI { [CmdletBinding()] param() }
    function global:Register-AzStackHCI { [CmdletBinding()] param($SubscriptionId, $TenantId, $Region, $ResourceGroupName, $ResourceName,
        [switch]$RepairRegistration, [switch]$UseDeviceAuthentication, $ArmAccessToken, $AccountId, $ComputerName, $Credential) }
    function global:Get-AzContext { [CmdletBinding()] param() }
    function global:Connect-AzAccount { [CmdletBinding(SupportsShouldProcess = $true)] param($Tenant, $TenantId, $Subscription, $SubscriptionId, [switch]$UseDeviceAuthentication) }
    function global:Get-ClusterNode { [CmdletBinding()] param() }

    . $script:ScriptPath

    $script:Tenant = '11111111-1111-1111-1111-111111111111'
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    $script:Rg = 'rg-local'
    $script:Name = 'Cluster01'
    $script:ResId = "/subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.AzureStackHCI/clusters/$($script:Name)"
    $script:OldPid = '33333333-3333-3333-3333-333333333333'
    $script:NewPid = '44444444-4444-4444-4444-444444444444'
    $script:CloudId = '55555555-5555-5555-5555-555555555555'
    if (-not $env:COMPUTERNAME) { $env:COMPUTERNAME = 'NODE1' }

    function script:New-Config([hashtable]$Override = @{}, [string[]]$Remove = @()) {
        $c = [ordered]@{
            tenantId = $script:Tenant; subscriptionId = $script:Sub; resourceGroupName = $script:Rg
            clusterName = $script:Name; region = 'westeurope'; logDirectory = (Join-Path $TestDrive 'logs')
            pollIntervalSeconds = 1; identityTimeoutSeconds = 5; propagationWaitSeconds = 1; syncWatchMinutes = 1
        }
        foreach ($k in $Override.Keys) { $c[$k] = $Override[$k] }
        foreach ($k in $Remove) { $c.Remove($k) }
        $p = Join-Path $TestDrive ("cfg-" + [guid]::NewGuid().ToString('N') + '.json')
        $c | ConvertTo-Json | Set-Content -Path $p -Encoding utf8
        return $p
    }
    function script:Resp([int]$Code, $Body, $Headers = @{}) {
        [pscustomobject]@{ StatusCode = $Code; Content = $(if ($null -eq $Body) { '' } else { $Body | ConvertTo-Json -Depth 10 }); Headers = $Headers }
    }
    function script:Code($Out) { return [int](@($Out)[-1]) }
}

Describe 'Repair-AzureLocalClusterIdentity' {
BeforeEach {
    # World state for the mocks
    $script:Calls = New-Object System.Collections.Generic.List[string]
    $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:OldPid; tenantId = $script:Tenant }
    $script:Location = 'westeurope'
    $script:Locks = @(@{ name = 'DoNotDelete'; properties = @{ level = 'CanNotDelete' } })
    $script:RoleAssignments = @()
    $script:PatchCode = @{ None = 200; SystemAssigned = 200 }
    $script:AssignGivesPrincipal = $true
    $script:AsyncOnPatch = $false
    $script:RegisterResult = 'Success'
    $script:Synced = $false
    $script:SyncConnects = $true
    $script:ContextTenant = $script:Tenant
    $script:ContextSub = $script:Sub
    $script:LocalUri = "/Subscriptions/$($script:Sub)/resourceGroups/$($script:Rg)/providers/Microsoft.AzureStackHCI/clusters/$($script:Name.ToLower())"
    $script:Before = [datetime]'2026-09-15T00:59:30Z'
    # Round-2 additions (review r1 + CI r1)
    $script:RaContent = $null; $script:RaCode = 200; $script:RaPaged = $false
    $script:LockContent = $null
    $script:AsyncMode = 'AzureAsync'; $script:LocPolls = 0
    $script:GetFaultAlways = $null; $script:GetFaults = New-Object System.Collections.Generic.Queue[string]
    $script:StripLeavesEmptyType = $false; $script:AssignThrows = $false
    $script:RegisterFormatted = $false; $script:RegisterDisconnects = $false
    $script:AssignCount = 0
    $script:RegisterAnsi = $false; $script:FinalGet403 = $false; $script:PatchRetryAfter = $null

    Mock Test-IsAdministrator { $true }
    $script:Slept = New-Object System.Collections.Generic.List[double]
    Mock Start-Sleep { $script:Slept.Add([double]$(if ($Milliseconds) { $Milliseconds / 1000.0 } else { $Seconds })) }
    Mock Get-ClusterNode { @([pscustomobject]@{ Name = $env:COMPUTERNAME; State = 'Up' }, [pscustomobject]@{ Name = [Environment]::MachineName; State = 'Up' }, [pscustomobject]@{ Name = 'NODE2'; State = 'Up' }) }
    Mock Get-AzureStackHCI {
        if ($script:Synced -and $script:SyncConnects) {
            [pscustomobject]@{ AzureResourceUri = $script:LocalUri; RegistrationStatus = 'Registered'; ConnectionStatus = 'Connected'; LastConnected = (Get-Date).ToUniversalTime() }
        } else {
            [pscustomobject]@{ AzureResourceUri = $script:LocalUri; RegistrationStatus = 'Registered'; ConnectionStatus = 'NotRecently'; LastConnected = $script:Before }
        }
    }
    Mock Get-AzContext {
        if ($null -eq $script:ContextTenant) { return $null }
        [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = $script:ContextTenant }; Subscription = [pscustomobject]@{ Id = $script:ContextSub } }
    }
    # Like the real cmdlet: under -WhatIf it does not sign in.
    Mock Connect-AzAccount { $script:Calls.Add('Connect'); if ($WhatIfPreference -and -not ($PSBoundParameters.ContainsKey('WhatIf') -and -not $WhatIf)) { return }; $script:ContextTenant = $script:Tenant; $script:ContextSub = $script:Sub }
    $script:ModVersions = @{ 'Az.Accounts' = '5.3.4'; 'Az.Resources' = '7.0.0'; 'Az.StackHCI' = '2.7.1' }
    Mock Get-Module -ParameterFilter { $ListAvailable } { foreach ($n in @($Name)) { if ($script:ModVersions[$n]) { [pscustomobject]@{ Name = $n; Version = [version]$script:ModVersions[$n] } } } }
    $script:ChangeOnSecondGet = $false; $script:PrePatchGets = 0
    Mock Register-AzStackHCI {
        $script:Calls.Add('Register')
        if ($script:RegisterDisconnects) { $script:ContextTenant = $null }
        $o = [pscustomobject]@{ Result = $script:RegisterResult; ResourceId = '/x' }
        if ($script:RegisterAnsi) { $e = [char]27; return @('', "$e[32;1mResult     : $e[0mSuccess", "$e[32;1mResourceId : $e[0m/x", '') }
        if ($script:RegisterFormatted) { $o | Format-List } else { $o }
    }
    Mock Sync-AzureStackHCI { $script:Calls.Add('Sync'); $script:Synced = $true }
    Mock Invoke-AzRestMethod {
        if ($Uri) {
            if ($Uri -match 'next1') { $script:Calls.Add('GET-RA2'); return (Resp 200 @{ value = @(@{ id = '/x/ra-page2'; properties = @{ principalId = $script:OldPid } }) }) }
            if ($Uri -match 'loc/1') {
                $script:Calls.Add('ASYNC'); $script:LocPolls++
                if ($script:LocPolls -lt 2) { return (Resp 202 $null @{ 'Location' = @('https://management.azure.com/loc/1'); 'Retry-After' = @('1') }) }
                return [pscustomobject]@{ StatusCode = 200; Content = ''; Headers = @{} }
            }
            $script:Calls.Add('ASYNC'); return (Resp 200 @{ status = 'Succeeded' })
        }
        if ($Path -match 'roleAssignments') {
            $script:Calls.Add('GET-RA')
            if ($null -ne $script:RaContent) { return [pscustomobject]@{ StatusCode = $script:RaCode; Content = $script:RaContent; Headers = @{} } }
            if ($script:RaPaged) { return (Resp 200 @{ value = @(@{ id = '/x/ra-page1'; properties = @{ principalId = $script:OldPid } }); nextLink = 'https://management.azure.com/next1' }) }
            return (Resp $script:RaCode @{ value = @($script:RoleAssignments) })
        }
        if ($Path -match '/locks') {
            $script:Calls.Add('GET-LOCKS')
            if ($null -ne $script:LockContent) { return [pscustomobject]@{ StatusCode = 200; Content = $script:LockContent; Headers = @{} } }
            return (Resp 200 @{ value = @($script:Locks) })
        }
        if ($Method -eq 'PATCH') {
            $t = ($Payload | ConvertFrom-Json).identity.type
            $script:Calls.Add("PATCH-$t")
            if ($t -eq 'SystemAssigned' -and $script:AssignThrows) { throw 'The remote name could not be resolved' }
            $code = $script:PatchCode[$t]
            if ($code -ge 200 -and $code -lt 300) {
                if ($t -eq 'None') { if ($script:StripLeavesEmptyType) { $script:Identity = @{ type = '' } } else { $script:Identity = $null } }
                elseif ($script:AssignGivesPrincipal) {
                    # A new principal per assignment (the first one is NewPid), like Azure does.
                    $script:AssignCount++
                    $p = $(if ($script:AssignCount -eq 1) { $script:NewPid } else { [guid]::NewGuid().ToString() })
                    $script:Identity = @{ type = 'SystemAssigned'; principalId = $p; tenantId = $script:Tenant }
                }
            }
            if ($script:AsyncOnPatch -and $code -eq 200) {
                if ($script:AsyncMode -eq 'Location') { $script:LocPolls = 0; return (Resp 202 $null @{ 'Location' = @('https://management.azure.com/loc/1') }) }
                $h = @{ 'Azure-AsyncOperation' = @('https://management.azure.com/op/1') }
                if ($script:PatchRetryAfter) { $h['Retry-After'] = @("$($script:PatchRetryAfter)") }
                return (Resp 202 $null $h)
            }
            return (Resp $code @{ error = @{ code = 'X'; message = 'mock' } })
        }
        if ($Path -match 'Microsoft.AzureStackHCI/clusters/') {
            $script:Calls.Add('GET-RES')
            if (-not $script:Calls.Contains('PATCH-None')) { $script:PrePatchGets++; if ($script:ChangeOnSecondGet -and $script:PrePatchGets -eq 2) { $script:Identity = @{ type = 'SystemAssigned'; principalId = '77777777-7777-7777-7777-777777777777' } } }
            if ($script:FinalGet403 -and $script:Calls.Contains('Register')) { return (Resp 403 @{ error = @{ code = 'AuthorizationFailed'; message = 'no access' } }) }
            if ($script:Calls.Contains('PATCH-None')) {
                $f = $script:GetFaultAlways
                if (-not $f -and $script:GetFaults.Count -gt 0) { $f = $script:GetFaults.Dequeue() }
                if ($f -eq 'invalid') { return [pscustomobject]@{ StatusCode = 200; Content = '<html>gateway</html>'; Headers = @{} } }
                if ($f -eq '500') { return (Resp 500 @{ error = @{ code = 'InternalServerError' } }) }
                if ($f -eq '429') { return (Resp 429 @{ error = @{ code = 'TooManyRequests' } } @{ 'Retry-After' = @('2') }) }
                if ($f -eq '429long') { return (Resp 429 @{ error = @{ code = 'TooManyRequests' } } @{ 'Retry-After' = @('600') }) }
                if ($f -eq 'throw') { throw 'An error occurred while sending the request.' }
            }
            $body = @{ id = $script:ResId; name = $script:Name; location = $script:Location; properties = @{ cloudId = $script:CloudId; lastSyncTimestamp = '2026-09-15T00:59:32Z' } }
            if ($script:Identity) { $body.identity = $script:Identity }
            return (Resp 200 $body)
        }
        return (Resp 404 @{ error = @{ code = 'NotFound' } })
    }
}

Describe 'Shareability and compatibility' {
    It 'script exists and parses without errors' {
        $e = $null; [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$e) | Out-Null
        $e | Should -BeNullOrEmpty
    }
    It 'uses no PowerShell 7-only operators' {
        $t = $null; $e = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$t, [ref]$e) | Out-Null
        ($t | Where-Object { "$($_.Kind)" -in 'QuestionQuestion', 'QuestionQuestionEquals', 'AndAnd', 'OrOr', 'QuestionDot', 'QuestionLBracket' }) | Should -BeNullOrEmpty
        (Get-Content $script:ScriptPath -Raw) | Should -Not -Match '-Parallel\b'
    }
    It 'contains no GUIDs or customer names (script, README, example config)' {
        foreach ($f in 'Repair-AzureLocalClusterIdentity.ps1', 'README.md', 'config.example.json') {
            $p = Join-Path $script:Root $f
            Test-Path $p | Should -BeTrue -Because "$f must exist"
            $txt = Get-Content $p -Raw
            $txt | Should -Not -Match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
            # Terms that must not appear (operator-specific names) come from the environment, so this file names none.
            $terms = @(($env:CIR_FORBIDDEN_TERMS -split ';') | Where-Object { $_ })
            if ($env:CIR_FORBIDDEN_TERMS_FILE -and (Test-Path $env:CIR_FORBIDDEN_TERMS_FILE)) { $terms += @(Get-Content $env:CIR_FORBIDDEN_TERMS_FILE | Where-Object { $_.Trim() }) }
            foreach ($term in $terms) { $txt | Should -Not -Match ([regex]::Escape($term)) }
        }
    }
    It 'has comment-based help with synopsis and examples' {
        $h = Get-Help $script:ScriptPath -Full
        $h.Synopsis | Should -Not -BeNullOrEmpty
        @($h.Examples.Example).Count | Should -BeGreaterThan 0
    }
    It 'example config lists every required field' {
        $c = Get-Content (Join-Path $script:Root 'config.example.json') -Raw | ConvertFrom-Json
        foreach ($k in 'tenantId', 'subscriptionId', 'resourceGroupName', 'clusterName', 'region') { $c.PSObject.Properties.Name | Should -Contain $k }
    }
}

Describe 'Config validation (exit 7, no Azure call)' {
    It 'missing file' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (Join-Path $TestDrive 'nope.json') -Confirm:$false) | Should -Be 7
        Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly
    }
    It 'missing required field' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config -Remove 'region') -Confirm:$false) | Should -Be 7
        Should -Invoke Invoke-AzRestMethod -Times 0 -Exactly
    }
    It 'non-GUID tenant' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ tenantId = 'contoso' }) -Confirm:$false) | Should -Be 7
    }
    It 'unknown key' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ clustername2 = 'x' }) -Confirm:$false) | Should -Be 7
    }
}

Describe 'Pre-flight failures (exit 1, no write)' {
    It 'not administrator' {
        Mock Test-IsAdministrator { $false }
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
    It 'local registration points to another resource' {
        $script:LocalUri = "/Subscriptions/$($script:Sub)/resourceGroups/other/providers/Microsoft.AzureStackHCI/clusters/other"
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
    It 'region differs from the resource location' {
        $script:Location = 'northeurope'
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
    It 'expectedCloudId mismatch' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ expectedCloudId = '66666666-6666-6666-6666-666666666666' }) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
    It 'ReadOnly lock' {
        $script:Locks = @(@{ name = 'ro'; properties = @{ level = 'ReadOnly' } })
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
    It 'role assignments exist and loss not accepted; they are exported' {
        $script:RoleAssignments = @(@{ id = '/x/ra1'; properties = @{ principalId = $script:OldPid; roleDefinitionId = '/r/1'; scope = '/subscriptions/x' } })
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'role-assignments-before.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        $f | Should -Not -BeNullOrEmpty
        (Get-Content $f.FullName -Raw) | Should -Match 'ra1'
    }
    It 'wrong Azure context triggers Connect-AzAccount with the config tenant and subscription' {
        $script:ContextTenant = '99999999-9999-9999-9999-999999999999'
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter { (@($Tenant, $TenantId) -contains $script:Tenant) -and (@($Subscription, $SubscriptionId) -contains $script:Sub) }
    }
    It 'context still wrong after sign-in' {
        $script:ContextTenant = '99999999-9999-9999-9999-999999999999'
        Mock Connect-AzAccount { }
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }
}

Describe 'WhatIf' {
    It 'makes no write and returns 0' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -WhatIf) | Should -Be 0
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        Should -Invoke Sync-AzureStackHCI -Times 0 -Exactly
    }
}

Describe 'Happy path' {
    It 'runs strip, assign, repair, sync in order and returns 0' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        $w = @($script:Calls | Where-Object { $_ -in 'PATCH-None', 'PATCH-SystemAssigned', 'Register', 'Sync' })
        ($w -join ',') | Should -Be 'PATCH-None,PATCH-SystemAssigned,Register,Sync'
    }
    It 'calls Register-AzStackHCI with the config values and -RepairRegistration' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        Should -Invoke Register-AzStackHCI -Times 1 -Exactly -ParameterFilter {
            $SubscriptionId -eq $script:Sub -and $TenantId -eq $script:Tenant -and $Region -eq 'westeurope' -and
            $ResourceGroupName -eq $script:Rg -and $ResourceName -eq $script:Name -and $RepairRegistration }
    }
    It 'checks the identity is gone before assigning (GET between the two PATCHes)' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        $a = $script:Calls.IndexOf('PATCH-None'); $b = $script:Calls.IndexOf('PATCH-SystemAssigned')
        @($script:Calls[($a + 1)..($b - 1)]) | Should -Contain 'GET-RES'
    }
    It 'checks the new principal before Register (GET between assign and Register)' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        $a = $script:Calls.IndexOf('PATCH-SystemAssigned'); $b = $script:Calls.IndexOf('Register')
        @($script:Calls[($a + 1)..($b - 1)]) | Should -Contain 'GET-RES'
    }
    It 'writes summary.json with exit code, old and new principal' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'summary.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        $s = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $s.exitCode | Should -Be 0
        $s.oldPrincipalId | Should -Be $script:OldPid
        $s.newPrincipalId | Should -Be $script:NewPid
        @($s.steps).Count | Should -BeGreaterThan 0
    }
    It 'follows Azure-AsyncOperation on 202 before continuing' {
        $script:AsyncOnPatch = $true
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        $a = $script:Calls.IndexOf('PATCH-None'); $b = $script:Calls.IndexOf('PATCH-SystemAssigned')
        @($script:Calls[($a + 1)..($b - 1)]) | Should -Contain 'ASYNC'
    }
    It 'accepts role-assignment loss when told to' {
        $script:RoleAssignments = @(@{ id = '/x/ra1'; properties = @{ principalId = $script:OldPid } })
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -AcceptRoleAssignmentLoss -Confirm:$false) | Should -Be 0
    }
}

Describe 'Failures during write steps' {
    It 'strip PATCH rejected: exit 3, nothing else written' {
        $script:PatchCode.None = 409
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
        $script:Calls | Should -Not -Contain 'PATCH-SystemAssigned'
        Should -Invoke Register-AzStackHCI -Times 0 -Exactly
    }
    It 'assign PATCH rejected: exit 4 and the resume command is logged' {
        $script:PatchCode.SystemAssigned = 500
        $out = Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false 6>&1 4>&1 3>&1
        Code $out | Should -Be 4
        Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -File | Sort-Object LastWriteTime | Select-Object -Last 5
        ((($f | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n") + ($out -join "`n")) | Should -Match 'ResumeFrom\s+AssignIdentity'
    }
    It 'no new principal appears within the timeout: exit 4' {
        $script:AssignGivesPrincipal = $false
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 4
        Should -Invoke Register-AzStackHCI -Times 0 -Exactly
    }
    It 'Register-AzStackHCI fails: exit 5, no sync' {
        $script:RegisterResult = 'Failed'
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 5
        Should -Invoke Sync-AzureStackHCI -Times 0 -Exactly
    }
    It 'Register-AzStackHCI throws: exit 5' {
        Mock Register-AzStackHCI { throw 'MsiProvisionFailed' }
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 5
    }
    It 'sync never connects: exit 6' {
        $script:SyncConnects = $false
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 6
    }
    It 'summary.json is written on a failure path too' {
        $script:PatchCode.None = 409
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
        $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'summary.json' | Sort-Object LastWriteTime | Select-Object -Last 1
        (Get-Content $f.FullName -Raw | ConvertFrom-Json).exitCode | Should -Be 3
    }
}

Describe 'Resume' {
    It 'AssignIdentity skips the strip' {
        $script:Identity = $null
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -ResumeFrom AssignIdentity -Confirm:$false) | Should -Be 0
        $script:Calls | Should -Not -Contain 'PATCH-None'
        $script:Calls | Should -Contain 'PATCH-SystemAssigned'
    }
    It 'RepairRegistration makes no PATCH' {
        $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:NewPid }
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -ResumeFrom RepairRegistration -Confirm:$false) | Should -Be 0
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        Should -Invoke Register-AzStackHCI -Times 1 -Exactly
    }
    It 'Verify only syncs and checks' {
        Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -ResumeFrom Verify -Confirm:$false) | Should -Be 0
        Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        Should -Invoke Sync-AzureStackHCI -Times 1 -Exactly
    }
}

    Describe 'Round 2: real Az.StackHCI output and session' {
        It 'accepts Register-AzStackHCI output as Format-List records (Success)' {
            $script:RegisterFormatted = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        }
        It 'rejects Format-List output showing Failed' {
            $script:RegisterFormatted = $true; $script:RegisterResult = 'Failed'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 5
        }
        It 'still succeeds when Register-AzStackHCI disconnects the Azure session' {
            $script:RegisterDisconnects = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        }
    }

    Describe 'Round 2: reads that fail are not "nothing found"' {
        It 'malformed role-assignment body: exit 1, no write' {
            $script:RaContent = 'not json'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'role-assignment read forbidden (403): exit 1, no write' {
            $script:RaCode = 403
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'role-assignment body without value array: exit 1' {
            $script:RaContent = '{"something":1}'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        }
        It 'malformed lock body: exit 1, no write' {
            $script:LockContent = ''
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'follows nextLink and exports every role-assignment page' {
            $script:RaPaged = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'role-assignments-before.json' | Sort-Object LastWriteTime | Select-Object -Last 1
            $t = Get-Content $f.FullName -Raw
            $t | Should -Match 'ra-page1'
            $t | Should -Match 'ra-page2'
        }
    }

    Describe 'Round 2: strip and assign are verified strictly' {
        It 'an unparsable resource body is not proof of removal: exit 3, no assign' {
            $script:GetFaultAlways = 'invalid'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
            $script:Calls | Should -Not -Contain 'PATCH-SystemAssigned'
        }
        It 'an identity with an empty type is not proof of removal: exit 3, no assign' {
            $script:StripLeavesEmptyType = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
            $script:Calls | Should -Not -Contain 'PATCH-SystemAssigned'
        }
        It 'transient 500, 429 and transport errors during polling are retried' {
            foreach ($x in '500', '429', 'throw') { $script:GetFaults.Enqueue($x) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        }
        It 'an exception on the assign PATCH after a successful strip: exit 4 recorded in summary' {
            $script:AssignThrows = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 4
            Should -Invoke Register-AzStackHCI -Times 0 -Exactly
            $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'summary.json' | Sort-Object LastWriteTime | Select-Object -Last 1
            (Get-Content $f.FullName -Raw | ConvertFrom-Json).exitCode | Should -Be 4
        }
        It 'follows the Location protocol (202 then 200 with no status body)' {
            $script:AsyncOnPatch = $true; $script:AsyncMode = 'Location'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        }
        It 'resume AssignIdentity when the identity already exists: no PATCH, continues to Register' {
            $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:NewPid }
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('fresh-' + [guid]::NewGuid().ToString('N'))) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -PreviousPrincipalId $script:OldPid -Confirm:$false) | Should -Be 0
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
            Should -Invoke Register-AzStackHCI -Times 1 -Exactly
        }
    }

    Describe 'Round 2: housekeeping' {
        It 'no transcript is left running after a successful run' {
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
            { Stop-Transcript -ErrorAction Stop } | Should -Throw
        }
        It 'no transcript is left running after a failed run' {
            $script:PatchCode.None = 409
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
            { Stop-Transcript -ErrorAction Stop } | Should -Throw
        }
        It 'two runs in a row write two separate run folders' {
            $logs = Join-Path $TestDrive 'logs'
            $n0 = @(Get-ChildItem -Path $logs -Recurse -Filter 'summary.json' -ErrorAction SilentlyContinue).Count
            $cfg = New-Config
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 0
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 0
            @(Get-ChildItem -Path $logs -Recurse -Filter 'summary.json').Count | Should -Be ($n0 + 2)
        }
        It 'README states that orphaned role assignments are not deleted' {
            (Get-Content (Join-Path $script:Root 'README.md') -Raw) | Should -Match '(?i)orphan'
        }
    }

    Describe 'Round 3: review r2' {
        It 'accepts ANSI-decorated Format-List output showing Success' {
            $script:RegisterAnsi = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
        }
        It 'a long Retry-After cannot stretch a step beyond its timeout' {
            $script:GetFaultAlways = '429long'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 3
            ($script:Slept | Measure-Object -Sum).Sum | Should -BeLessOrEqual 10
            $script:Calls | Should -Not -Contain 'PATCH-SystemAssigned'
        }
        It 'honours Retry-After on a 202 PATCH response before the first poll' {
            $script:AsyncOnPatch = $true; $script:PatchRetryAfter = 7
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ identityTimeoutSeconds = 30 }) -Confirm:$false) | Should -Be 0
            @($script:Slept | Where-Object { $_ -ge 7 }).Count | Should -BeGreaterThan 0
        }
        It 'an error response is never saved as after.json cluster evidence' {
            $script:FinalGet403 = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 0
            $f = Get-ChildItem -Path (Join-Path $TestDrive 'logs') -Recurse -Filter 'after.json' | Sort-Object LastWriteTime | Select-Object -Last 1
            if ($f) { (Get-Content $f.FullName -Raw) | Should -Not -Match 'AuthorizationFailed' }
        }
        It 'function names use approved verbs' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $verbs = (Get-Verb).Verb
            $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
            foreach ($fn in $fns) { $verbs | Should -Contain ($fn.Name -split '-')[0] -Because $fn.Name }
        }
    }

    Describe 'Round 4: docs review (resume and confirmation safety)' {
        It 'resume AssignIdentity refuses when the old identity is still present (from the previous summary)' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r4a-' + [guid]::NewGuid().ToString('N'))) }
            $script:PatchCode.None = 409
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 3
            $script:PatchCode.None = 200; $script:Calls.Clear()
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -Confirm:$false) | Should -Be 1
            $script:Calls | Should -Not -Contain 'PATCH-SystemAssigned'
            $script:Calls | Should -Not -Contain 'Register'
        }
        It 'resume AssignIdentity with an identity present and no way to know the old one: exit 1' {
            $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:NewPid }
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r4b-' + [guid]::NewGuid().ToString('N'))) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -Confirm:$false) | Should -Be 1
            Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        }
        It 'resume AssignIdentity refuses when -PreviousPrincipalId equals the present principal' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r4c-' + [guid]::NewGuid().ToString('N'))) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -PreviousPrincipalId $script:OldPid -Confirm:$false) | Should -Be 1
            Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        }
        It 'a resume does not require -AcceptRoleAssignmentLoss (the present principal is the new one)' {
            $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:NewPid }
            $script:RoleAssignments = @(@{ id = '/x/ra-new'; properties = @{ principalId = $script:NewPid } })
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -ResumeFrom RepairRegistration -Confirm:$false) | Should -Be 0
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'refuses a resource that also has user-assigned identities' {
            $script:Identity = @{ type = 'SystemAssigned, UserAssigned'; principalId = $script:OldPid; userAssignedIdentities = @{ '/x/uai' = @{} } }
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'one confirmation covers both identity PATCHes (WhatIf lists the replacement once)' {
            $out = Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -WhatIf 6>&1 4>&1 3>&1 2>&1
            Code $out | Should -Be 0
            $t = ($out | Out-String)
            ([regex]::Matches($t, '(?i)What if:.*identity')).Count | Should -Be 1
        }
    }

    Describe 'Round 5: cross-vendor safety review' {
        It '-WhatIf still signs in (Connect-AzAccount is not suppressed)' {
            $script:ContextTenant = '99999999-9999-9999-9999-999999999999'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -WhatIf) | Should -Be 0
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'identity changed between plan and confirmation: exit 1, no write' {
            $script:ChangeOnSecondGet = $true
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'too old Az.Resources: exit 1 before any write' {
            $script:ModVersions['Az.Resources'] = '5.0.0'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
            Should -Invoke Invoke-AzRestMethod -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
        }
        It 'too old Az.Accounts: exit 1 before any write' {
            $script:ModVersions['Az.Accounts'] = '2.7.0'
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false) | Should -Be 1
        }
        It 'a WhatIf summary never feeds the resume check' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r5a-' + [guid]::NewGuid().ToString('N'))) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -WhatIf) | Should -Be 0
            $script:Identity = @{ type = 'SystemAssigned'; principalId = $script:NewPid }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -Confirm:$false) | Should -Be 1
            Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        }
        It 'resume RepairRegistration without an identity: exit 1' {
            $script:Identity = $null
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -ResumeFrom RepairRegistration -Confirm:$false) | Should -Be 1
            Should -Invoke Register-AzStackHCI -Times 0 -Exactly
        }
        It 'resume commands quote the config path with single quotes' {
            $script:PatchCode.SystemAssigned = 500
            $out = Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false 6>&1 4>&1 3>&1
            Code $out | Should -Be 4
            ($out | Out-String) | Should -Match "-ConfigPath '"
        }
        It 'rejects a cluster name with a slash' {
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ clusterName = 'c1/x' }) -Confirm:$false) | Should -Be 7
        }
        It 'rejects a region with spaces' {
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ region = 'west europe' }) -Confirm:$false) | Should -Be 7
        }
    }

    Describe 'Round 6: verification review' {
        It 'resume refuses a principal that an earlier failed strip tried to remove' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r6a-' + [guid]::NewGuid().ToString('N'))) }
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 0
            $p1 = $script:Identity.principalId
            $script:Synced = $false
            $script:PatchCode.None = 409
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 3
            $script:PatchCode.None = 200; $script:Calls.Clear()
            $script:Identity.principalId | Should -Be $p1
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -ResumeFrom AssignIdentity -Confirm:$false) | Should -Be 1
            $script:Calls | Should -Not -Contain 'Register'
        }
        It 'an unexpected error during verification returns 6 instead of escaping' {
            Mock Sync-AzureStackHCI { $script:Calls.Add('Sync'); $script:Synced = $true }
            Mock Get-AzureStackHCI {
                if ($script:Synced) { [pscustomobject]@{ AzureResourceUri = $script:LocalUri; RegistrationStatus = 'Registered'; ConnectionStatus = 'Connected'; LastConnected = 'not a date' } }
                else { [pscustomobject]@{ AzureResourceUri = $script:LocalUri; RegistrationStatus = 'Registered'; ConnectionStatus = 'NotRecently'; LastConnected = $script:Before } }
            }
            { $script:r6 = Invoke-ClusterIdentityRepair -ConfigPath (New-Config) -Confirm:$false } | Should -Not -Throw
            Code $script:r6 | Should -Be 6
        }
        It 'not administrator: no evidence folder is created' {
            Mock Test-IsAdministrator { $false }
            $ld = Join-Path $TestDrive ('r6c-' + [guid]::NewGuid().ToString('N'))
            Code (Invoke-ClusterIdentityRepair -ConfigPath (New-Config @{ logDirectory = $ld }) -Confirm:$false) | Should -Be 1
            Test-Path $ld | Should -BeFalse
        }
    }

    Describe 'Round 7: final validation' {
        It 'a plain re-run after a completed replacement refuses to strip the new identity' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r7a-' + [guid]::NewGuid().ToString('N'))) }
            $script:RegisterResult = 'Failed'
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 5
            $script:RegisterResult = 'Success'; $script:Calls.Clear()
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 1
            $script:Calls | Should -Not -Contain 'PATCH-None'
        }
        It 'the same re-run is allowed with -AllowRepeatReplacement' {
            $cfg = New-Config @{ logDirectory = (Join-Path $TestDrive ('r7b-' + [guid]::NewGuid().ToString('N'))) }
            $script:RegisterResult = 'Failed'
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -Confirm:$false) | Should -Be 5
            $script:RegisterResult = 'Success'
            Code (Invoke-ClusterIdentityRepair -ConfigPath $cfg -AllowRepeatReplacement -Confirm:$false) | Should -Be 0
        }
    }
}
