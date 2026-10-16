#requires -Version 7.0
<#
.SYNOPSIS
Exports sanitized, production validation evidence without changing Azure resources.
.DESCRIPTION
Writes validation-run-details.json and validation-report.md in WorkDirectory. Exit
codes: 0 = complete and ready; 1 = complete but not ready; 2 = incomplete or blocked.
Dot-source this file to use the offline helpers without Azure CLI or file writes.
Only explicitly linked child runs are collected; no "latest run" substitution occurs.

MetadataPath is optional JSON with these optional fields:
 environment: tenantId, subscriptionId, resourceGroupName, logicAppName,
   managedIdentity, entraApplication, servicePrincipal, provisioningJob, endpoint,
   operatorIdentity (supply identifiers, not credential/configuration objects).
 supportedAuthenticationMethods: array containing Bearer, OAuth2ClientCredentials,
   WorkloadIdentityFederation (authenticationMethods is accepted as an alias).
 applicability: object keyed by exact testName, each { applicable: false, reason: ... }.
 preflight: { status: Blocked, reason: ..., startTime: ..., endTime: ... }.
 provisioningLogPath: path to a supplied provisioning log (relative to WorkDirectory).
 agentRun: { startTime, endTime, status } (explicit setup-to-cleanup window,
   separate from the Azure Orchestrator window; timestamps may be null).
 agentEventsPath: path relative to WorkDirectory, or an absolute path, to a JSON
   array of { name, kind, parentName, startTime, endTime, status, details } events.
   Details are sanitized; unknown fields are ignored. Missing/open/invalid timings
   remain explicit and never receive export-time substitutes. Agent evidence is
   optional for historical runs and does not change Azure gallery readiness.
 harness: { name, version, model, reasoning, context } (explicit caller-supplied data only).
 knownSecrets: optional literal strings for in-memory defense-in-depth redaction.
 source: { repositoryUrl, revision, branch, dirty, description } (caller claims,
   stored separately from the locally observed agent/source Git provenance).
 historicalRun: { version, authenticationPolicy, selectedMethods, description }
   (caller-recorded deployed-run claims, never replaced with the current VERSION).
   sourceVersion: { value, sha256 } may record the original source VERSION bytes
   separately from that run's deployed version and the current reporting source.
   Successful content responses, including JSON null, empty strings, false, zero
   and empty arrays, are tracked independently of their values. A null downloaded
   body requires a recorded successful HTTP status; an absent output property or
   failed/unproven download remains unavailable.
   After dot-sourcing, Complete-ScimValidationReport -ReportPath <terminal-report>
   can correct the legacy empty-string Compose classification without any network
   requests. It requires collected empty-string inputs, a two-byte output link,
   matching classification failures and zero failed content requests. It never
   establishes gallery readiness or rewrites the source file. Write its returned
   report to a separate WorkDirectory with Write-ScimValidationReport.
 deploymentOverlay: { name, revision, sha256, description,
   workflowHashes: [ { name, sha256 } ] } (identifiers/hashes only; never contents).
 workflowRuns: [ { workflowName, runId, parentWorkflowName, parentRunId,
   parentActionName, repetitionName } ] (optional exact IDs supplied by caller,
   useful when secureData intentionally hides a Workflow call's run-ID header).
 environment values may be strings or identifier-only objects. Recommended objects:
   managedIdentity: { type, tenantId, principalId, clientId };
   entraApplication: { id, appId, displayName };
   servicePrincipal: { id, appId, displayName };
   provisioningJob: { id, servicePrincipalId };
   endpoint: { url, displayName, authenticationType };
   operatorIdentity: { id, displayName, userPrincipalName, type }.
 scimAuthenticationMethod: Bearer, OAuth2ClientCredentials or
   WorkloadIdentityFederation (direct request transport; independent of gallery
   supportedAuthenticationMethods).
 All fields are optional; omitted harness fields remain null with explicit reasons.
 Source/overlay metadata is caller-attributed, never treated as observed deployment
 equivalence. Unknown keys are ignored. workflowRuns contains no credentials.
 ARM credentials are refreshed using Azure CLI expires_on with a five-minute
 margin. An ARM HTTP 401 gets one credential refresh and one retry; final errors
 remain evidence failures. Credentials are never sent to signed content hosts.
 ResumeReportPath optionally reuses successfully collected sanitized payloads from
 terminal actions in a previous report for the same root/subscription/site. Run
 headers, action lists and repetition details are still read fresh. Missing/failed
 payloads are retried, old evidence failures are not inherited, and current metadata
 is applied normally. Reused payloads are labeled; this is not raw-response replay.
 The CLI saves sanitized evidence to validation-run-details.checkpoint.json at
 workflow boundaries and the first completed action, then at thirty-second
 intervals checked after each action and repetition. Matching root/site
 checkpoints resume automatically. Batching avoids repeatedly rewriting a large
 inventory for fast, skipped repetitions; no collected evidence is truncated.
 Complete repetition-list entries are used directly; incomplete entries still
 require detail requests. Skipped repetitions have no execution payload to fetch.
 Request count, failure count and total/maximum latency by category are recorded
 in runtime.evidenceRequests for checkpointed collection.
 The default FailureFocused diagnostic scope retains every action/repetition's
 metadata, timing and errors. It collects top-level action payloads and failed or
 timed-out repetition payloads. Successful repeated HTTP polls and control-flow
 repetitions retain metadata only; their payloads are explicitly out of scope.
 Semantic-result producers and child workflow calls remain payload-bearing even
 when successful. Completeness is assessed within this declared scope, subject
 to separately disclosed security exclusions; it never claims every payload.
 Checkpoints are incomplete; canonical reports are replaced only after collection.
 WorkflowDirectory VERSION value/hash identify current source, not deployed history.
Unknown metadata is ignored. Never pass parameters.json or appsettings as metadata.
Do not place credentials on a command line; prefer a caller-held KnownSecrets array.
Use an existing PowerShell process: & $exporter @arguments -KnownSecrets $secrets.
Do not interpolate secrets into pwsh -Command/-File arguments or write knownSecrets
to MetadataPath. This exporter never serializes the array or the ARM access token.

Every nested Workflow action and every returned action repetition is inspected for
an exact child run header, independently of the four historical Orchestrator calls.
Secured call headers are security exclusions, not failed payload downloads. Where
available, a separate, explicitly labeled correlation-only child-run inventory is
collected; it does not assert an exact parent-action mapping. Supply workflowRuns
for exact mappings if the service intentionally hides that association.

The JSON is canonicalized by key and contains no collection timestamp. Evidence
identifiers and UTC timings are preserved. Runtime status is separate from test
semantics. Missing evidence is recorded and prevents readiness.

ARM API reference:
https://learn.microsoft.com/rest/api/appservice/workflow-run-actions/list
.EXAMPLE
.\Export-ScimValidationReport.ps1 -WorkDirectory . -SubscriptionId $subscription `
  -ResourceGroupName $group -LogicAppName $app -OrchestratorRunId $run -AgentPath .\scim-onboarding.agent.md
#>
[CmdletBinding()]
param(
    [string] $WorkDirectory,
    [string] $SubscriptionId,
    [string] $ResourceGroupName,
    [string] $LogicAppName,
    [string] $OrchestratorRunId,
    [string] $AgentPath,
    [string] $MetadataPath,
    [string] $TenantId,
    [string] $WorkflowDirectory,
    [string] $ResumeReportPath,
    [string[]] $KnownSecrets = @(),
    [switch] $Zip
)

function Protect-ScimText {
    param([AllowEmptyString()][string] $Text, [string[]] $Secrets = @())
    $s = [System.Net.WebUtility]::HtmlDecode($Text)
    # Logs can embed escaped JSON outside an otherwise valid JSON document.
    for ($i = 0; $i -lt 3; $i++) {
        $s = $s.Replace('\"', '"')
        $s = [regex]::Replace($s, '\\u([0-9a-fA-F]{4})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) })
    }
    foreach ($secret in $Secrets) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            foreach ($literal in @($secret, [uri]::EscapeDataString($secret), [System.Net.WebUtility]::HtmlEncode($secret), [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($secret)))) {
                $s = $s.Replace($literal, '[REDACTED]')
            }
        }
    }
    $s = [regex]::Replace($s, '(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9_.~+/=%-]+', '[REDACTED AUTH]')
    $s = [regex]::Replace($s, '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', '[REDACTED TOKEN]')
    $s = [regex]::Replace($s, '(?i)(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature|SharedAccessKey|Password|Pwd)\s*=[^\r\n]*', '[REDACTED CONNECTION/CREDENTIAL]')
    $s = [regex]::Replace($s, '(?i)(?:Authorization|Proxy-Authorization|Set-Cookie|Cookie)\s*[:=]\s*[^\r\n]+', '[REDACTED HEADER]')
    # OAuth code labels must not match diagnostic suffixes such as StatusCode.
    $key = '(?:client[ _-]?secret|client[ _-]?assertion|assertion|password|passwd|secret|api[ _-]?key|subscription[ _-]?key|access[ _-]?token|id[ _-]?token|refresh[ _-]?token|token|sig|signature|(?<![\w-])(?:authorization[ _-]code|code)|credential)'
    $s = [regex]::Replace($s, "(?i)([`"']?$key[`"']?(?:\s*[:=]\s*|\s+is\s+))(?!(?:[`"'])?\[(?:REDACTED|OMITTED|EXCLUDED)\b)(?:`"[^`"]*`"|'[^']*'|[^\s&,;}\]]+)", '$1[REDACTED]')
    # Treat every URL query value as sensitive, including unrecognized/custom keys.
    $s = [regex]::Replace($s, '(?i)https?://(?:\[REDACTED[^\]]*\]|[^\s<>"''])+', {
        param($m)
        $url = $m.Value
        $url = [regex]::Replace($url, '^(https?://)[^/@\s]+:[^/@\s]+@', '$1[REDACTED]@')
        $url = [regex]::Replace($url, '\?[^#]*', '?[REDACTED QUERY]')
        [regex]::Replace($url, '#.*$', '#[REDACTED FRAGMENT]')
    })
    return $s
}

function Test-ScimSensitiveKey {
    param([string] $Name)
    $n = $Name -replace '[^a-zA-Z0-9]', ''
    return $n -match '(?i)(authorization|cookie|apikey|subscriptionkey|clientsecret|password|passwd|accesstoken|idtoken|refreshtoken|assertion|connectionstring|accountkey|sharedaccess|credential|signature)' -or
        $n -match '^(?i:secret|secrets|token|tokens|sig|key)$'
}

function Protect-ScimValue {
    param($Value, [string[]] $Secrets = @(), [string] $Name = '', [int] $Depth = 0)
    if ($Depth -gt 80) { return '[OMITTED: depth limit]' }
    if ((Test-ScimSensitiveKey $Name) -and $Name -ne 'rawCredentialsPersisted') { return '[REDACTED]' }
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $s = Protect-ScimText $Value $Secrets
        $trimmed = $Value.Trim()
        if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[') -or $trimmed.StartsWith('"')) {
            try {
                $embedded = ConvertFrom-Json -InputObject $Value -AsHashtable -ErrorAction Stop
                return (Protect-ScimValue $embedded $Secrets '' ($Depth + 1) | ConvertTo-Json -Depth 100 -Compress)
            } catch { }
        }
        # Encoded form bodies and error strings often carry JSON or secrets one layer down.
        if ($s -match '%[0-9a-fA-F]{2}') {
            $decoded = [uri]::UnescapeDataString($s)
            if ($decoded -ne $s) { return Protect-ScimValue $decoded $Secrets '' ($Depth + 1) }
        }
        return $s
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        $tokenPayload = $Value.Contains('access_token') -or $Value.Contains('id_token') -or $Value.Contains('refresh_token') -or
            $Value.Contains('client_secret') -or $Value.Contains('client_assertion')
        if ($tokenPayload) { return '[OMITTED: credential or token payload]' }
        foreach ($k in @($Value.Keys | Sort-Object -CaseSensitive)) {
            $safeKey = Protect-ScimText ([string]$k) $Secrets
            if ($Name -match '(?i)headers$' -and $k -notmatch '^(?i:content-type|content-length|date|retry-after|x-ms-request-id|x-ms-correlation-request-id|x-ms-client-tracking-id|x-ms-workflow-run-id|traceparent)$') {
                $result[$safeKey] = '[REDACTED: non-allowlisted header]'
            } else {
                $result[$safeKey] = Protect-ScimValue $Value[$k] $Secrets ([string]$k) ($Depth + 1)
            }
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return ,@($Value | ForEach-Object { Protect-ScimValue $_ $Secrets '' ($Depth + 1) })
    }
    return $Value
}

function ConvertTo-ScimCanonicalJson {
    param($Value)
    function Order-Value($v) {
        if ($v -is [System.Collections.IDictionary]) {
            $o = [ordered]@{}
            foreach ($k in @($v.Keys | Sort-Object -CaseSensitive)) { $o[$k] = Order-Value $v[$k] }
            return $o
        }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            return ,@($v | ForEach-Object { Order-Value $_ })
        }
        return $v
    }
    return (Order-Value $Value | ConvertTo-Json -Depth 100)
}

function Get-ScimTiming {
    param($Properties)
    $result = @{ startUtc = $null; endUtc = $null; durationMilliseconds = $null; unavailableReason = $null }
    try {
        foreach ($field in @('startTime', 'endTime')) {
            $value = $Properties.$field
            if (-not $value) { continue }
            # Newer PowerShell JSON parsers may return typed dates instead of strings.
            $utc = if ($value -is [datetimeoffset]) { $value.UtcDateTime }
                elseif ($value -is [datetime]) {
                    if ($value.Kind -eq [DateTimeKind]::Unspecified) { throw 'Timestamp has no explicit time zone.' }
                    $value.ToUniversalTime()
                } else {
                    if ([string]$value -notmatch '(?i)(Z|[+-]\d{2}:\d{2})$') { throw 'Timestamp has no explicit time zone.' }
                    ([datetimeoffset]::Parse([string]$value, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime
                }
            if ($field -eq 'startTime') { $result.startUtc = $utc.ToString('o') } else { $result.endUtc = $utc.ToString('o') }
        }
        if ($result.startUtc -and $result.endUtc) {
            $duration = ([datetimeoffset]::Parse($result.endUtc) - [datetimeoffset]::Parse($result.startUtc)).TotalMilliseconds
            if ($duration -lt 0) { throw 'End precedes start.' }
            $result.durationMilliseconds = $duration
        } else { $result.unavailableReason = 'Start or end time was not supplied by the evidence source.' }
    } catch { $result.unavailableReason = 'Invalid timing supplied by the evidence source.' }
    return $result
}

function Add-ScimEvidenceFailure {
    param($Context, [string] $Source, [string] $Reason, [bool] $Required = $true)
    $Context.failures.Add(@{ source = Protect-ScimText $Source $Context.secrets; reason = Protect-ScimText $Reason $Context.secrets; required = $Required })
}

function Get-ScimArmAuthentication {
    param([string] $SubscriptionId, [string] $TenantId, [scriptblock] $InvokeCli)
    $selector = if ($TenantId) { 'tenant' } else { 'subscription' }
    if (-not $TenantId -and -not $SubscriptionId) { throw 'An explicit tenant or subscription is required for ARM authentication.' }
    $commandArguments = @('account', 'get-access-token', '--resource', 'https://management.azure.com/', '--output', 'json', '--only-show-errors')
    # Azure CLI rejects using --tenant and --subscription together. ARM resource
    # URLs still select the requested subscription independently of token scope.
    if ($TenantId) { $commandArguments += @('--tenant', $TenantId) }
    else { $commandArguments += @('--subscription', $SubscriptionId) }
    if (-not $InvokeCli) {
        $InvokeCli = {
            param([string[]] $CommandArguments)
            $output = & az @CommandArguments 2>$null
            return @{ exitCode = $LASTEXITCODE; output = $output }
        }
    }
    $cliResult = & $InvokeCli $commandArguments
    if ($cliResult.exitCode -ne 0) { throw "Azure CLI ARM access token acquisition failed (selector: $selector; CLI exit $($cliResult.exitCode))." }
    try { $payload = ConvertFrom-Json -InputObject ($cliResult.output -join "`n") -AsHashtable -ErrorAction Stop }
    catch { throw 'Azure CLI returned an invalid ARM authentication response; raw output is intentionally omitted.' }
    if (-not $payload.accessToken) { throw 'Azure CLI returned no ARM access token.' }
    if ($TenantId -and $payload.tenant -and $payload.tenant -ne $TenantId) { throw 'Azure CLI returned ARM authentication for a different tenant than requested.' }
    $expiresUtc = $null
    if ($payload.expires_on) {
        try { $expiresUtc = [datetimeoffset]::FromUnixTimeSeconds([long]$payload.expires_on) }
        catch { throw 'Azure CLI returned an invalid expires_on value for ARM authentication.' }
    }
    return @{ accessToken = $payload.accessToken; tenant = $payload.tenant; selector = $selector; expiresUtc = $expiresUtc }
}

function New-ScimArmRequestState {
    param($Authentication, [string] $SubscriptionId, [string] $TenantId, [scriptblock] $Acquire, [scriptblock] $Send, [scriptblock] $Clock)
    if (-not $Acquire) { $Acquire = { param($subscription, $tenant) Get-ScimArmAuthentication -SubscriptionId $subscription -TenantId $tenant } }
    if (-not $Clock) { $Clock = { [datetimeoffset]::UtcNow } }
    if (-not $Send) {
        $Send = {
            param($uri, $headers, $receipt)
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -MaximumRedirection 0 -TimeoutSec 60 -StatusCodeVariable responseStatus -ErrorAction Stop
            if ($receipt) { $receipt.httpStatus = [int]$responseStatus }
            return ,$response
        }
    }
    $now = & $Clock
    $secrets = [System.Collections.Generic.List[string]]::new()
    if ($Authentication.accessToken) { $secrets.Add([string]$Authentication.accessToken) }
    return @{
        authentication = $Authentication; subscriptionId = $SubscriptionId; tenantId = $TenantId
        acquire = $Acquire; send = $Send; clock = $Clock; secretLiterals = $secrets
        acquiredUtc = $now; nextProactiveRefreshUtc = $now; refreshCount = 0; retry401Count = 0
    }
}

function Update-ScimArmAuthentication {
    param($State)
    $newAuthentication = & $State.acquire $State.subscriptionId $State.tenantId
    if (-not $newAuthentication.accessToken) { throw 'ARM authentication refresh returned no access token.' }
    $State.authentication = $newAuthentication
    if (-not $State.secretLiterals.Contains([string]$newAuthentication.accessToken)) { $State.secretLiterals.Add([string]$newAuthentication.accessToken) }
    $State.acquiredUtc = & $State.clock
    # Azure CLI can return the same cached near-expiry token. Avoid repeatedly
    # launching it for every request while retaining the bounded 401 recovery.
    $State.nextProactiveRefreshUtc = $State.acquiredUtc.AddSeconds(30)
    $State.refreshCount++
}

function Invoke-ScimRefreshingRequest {
    param($State, [string] $Uri, [bool] $Arm, [System.Collections.IDictionary] $Receipt)
    if (-not $Arm) { return ,(& $State.send $Uri @{} $Receipt) }
    $now = & $State.clock
    $expiry = $State.authentication.expiresUtc
    $needsRefresh = -not $State.authentication.accessToken -or
        ($expiry -and $expiry -le $now) -or
        ($expiry -and $expiry -le $now.AddMinutes(5) -and $now -ge $State.nextProactiveRefreshUtc) -or
        (-not $expiry -and $now -ge $State.acquiredUtc.AddMinutes(5))
    if ($needsRefresh) { Update-ScimArmAuthentication $State }
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            $headers = @{ Authorization = ('Bearer ' + $State.authentication.accessToken) }
            return ,(& $State.send $Uri $headers $Receipt)
        } catch {
            $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $_.Exception.Data['StatusCode'] }
            if ($attempt -eq 0 -and $status -eq 401) {
                $State.retry401Count++
                Update-ScimArmAuthentication $State
                continue
            }
            throw
        }
    }
}

function Invoke-ScimEvidenceRequest {
    param($Context, [string] $Uri, [bool] $Arm = $true, [bool] $Required = $true, [System.Collections.IDictionary] $Receipt)
    if ($null -eq $Receipt) { $Receipt = @{} }
    $Receipt.succeeded = $false
    $watch = if ($Context.requestMetricsEnabled) { [diagnostics.stopwatch]::StartNew() } else { $null }
    $requestFailed = $false
    try {
        $u = [uri]$Uri
        if ($u.Scheme -ne 'https' -or $u.UserInfo) { throw 'Evidence URI is not an approved HTTPS URI.' }
        if ($Arm -and $u.Host -ne 'management.azure.com') { throw 'ARM pagination cannot leave management.azure.com.' }
        if (-not $Arm -and $u.Host -notmatch '(^|\.)((azure\.com)|(windows\.net)|(azurewebsites\.net))$') {
            throw 'Content link host is not an approved Azure evidence host.'
        }
        $response = & $Context.request $Uri $Arm $Receipt
        if ($null -eq $response -and ($Arm -or $Receipt.httpStatus -lt 200 -or $Receipt.httpStatus -ge 300)) {
            throw 'Evidence source returned an empty response without successful HTTP content-response proof.'
        }
        $Receipt.succeeded = $true
        if ($response -is [System.Collections.IDictionary]) { return $response }
        if ($null -eq $response) { return $null }
        $normalized = ConvertTo-Json -InputObject $response -Depth 100 | ConvertFrom-Json -AsHashtable -NoEnumerate
        return ,$normalized
    } catch {
        $requestFailed = $true
        $Receipt.succeeded = $false
        Add-ScimEvidenceFailure $Context $Uri $_.Exception.Message $Required
        $failure = $Context.failures[$Context.failures.Count - 1]
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $_.Exception.Data['StatusCode'] }
        if ($status) { $failure.httpStatus = [int]$status }
        if ($_.ErrorDetails.Message) {
            $detail = $_.ErrorDetails.Message
            try { $detail = ConvertFrom-Json -InputObject $detail -AsHashtable -ErrorAction Stop } catch { }
            $failure.responseDetails = Protect-ScimValue $detail $Context.secrets
        }
        return $null
    } finally {
        if ($watch) {
            $category = if (-not $Arm) { 'ContentPayload' } elseif ($Uri -match '/(?:scopeRepetitions|repetitions)/[^/?]+\?') { 'RepetitionDetail' }
                elseif ($Uri -match '/(?:scopeRepetitions|repetitions)\?') { 'RepetitionList' } else { 'ArmMetadata' }
            if (-not $Context.requestMetrics.Contains($category)) {
                $Context.requestMetrics[$category] = @{ count = 0; failed = 0; totalMilliseconds = 0L; maximumMilliseconds = 0L }
            }
            $metric = $Context.requestMetrics[$category]
            $metric.count++
            if ($requestFailed) { $metric.failed++ }
            $metric.totalMilliseconds += $watch.ElapsedMilliseconds
            $metric.maximumMilliseconds = [Math]::Max($metric.maximumMilliseconds, $watch.ElapsedMilliseconds)
        }
    }
}

function Get-ScimEvidencePages {
    param($Context, [string] $Uri, [bool] $Required = $true)
    $items = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    while ($Uri) {
        if (-not $seen.Add($Uri)) { Add-ScimEvidenceFailure $Context $Uri 'Pagination cycle detected.' $Required; break }
        $page = Invoke-ScimEvidenceRequest $Context $Uri $true $Required
        if ($null -eq $page) { break }
        if ($page -is [System.Collections.IDictionary] -and $page.Contains('value')) {
            foreach ($entry in $page.value) { $items.Add($entry) }
            $Uri = $page.nextLink
        } elseif ($page -is [System.Collections.IEnumerable] -and $page -isnot [string] -and $page -isnot [System.Collections.IDictionary]) {
            foreach ($entry in $page) { $items.Add($entry) }
            $Uri = $null
        } else {
            Add-ScimEvidenceFailure $Context $Uri 'Collection response is neither a raw JSON array nor a value/nextLink envelope.' $Required
            break
        }
    }
    return ,@($items)
}

function Get-ScimDefinitionActions {
    param($Actions, [string] $Parent = '', [bool] $Repeated = $false)
    foreach ($name in @($Actions.Keys | Sort-Object)) {
        $a = $Actions[$name]
        @{ name = $name; type = $a.type; parent = $Parent; repeated = $Repeated
            targetWorkflow = $a.inputs.host.workflow.id; secureData = @($a.runtimeConfiguration.secureData.properties) }
        $loop = $Repeated -or $a.type -in @('Foreach', 'Until')
        if ($a.actions) { Get-ScimDefinitionActions $a.actions $name $loop }
        if ($a.else.actions) { Get-ScimDefinitionActions $a.else.actions $name $loop }
        if ($a.default.actions) { Get-ScimDefinitionActions $a.default.actions $name $loop }
        foreach ($case in @($a.cases.Values)) { if ($case.actions) { Get-ScimDefinitionActions $case.actions $name $loop } }
    }
}

function Test-ScimRepetitionPayloadRequired {
    param([string] $ActionType, [string] $ActionName, $Properties)
    if ($Properties.status -ne 'Succeeded' -or $Properties.error) { return $true }
    if ($ActionType -notin @('Http', 'Scope', 'Foreach', 'Until', 'Wait', 'If', 'Switch')) { return $true }
    if ($ActionName -match '(?i)(Final_?TestResults|Evaluate_?Test_?Results|Test_?Outputs|Test_?Results?|Semantic|_Test$)') { return $true }
    $output = $Properties.outputs
    if ($output.headers.'x-ms-workflow-run-id') { return $true }
    if ($output -is [System.Collections.IDictionary] -and $output.Contains('body')) { $output = $output.body }
    if ($output -is [System.Collections.IDictionary]) {
        foreach ($field in @('overallResult', 'testResult', 'result', 'testResults', 'authenticationModelResult')) {
            if ($output.Contains($field)) { return $true }
        }
    }
    return $false
}

function Get-ScimActionEvidence {
    param($Context, $Action, [string] $ActionUri, [bool] $Repeated = $false, [string[]] $SecureData = @(), [string] $ActionType = '',
        [switch] $IsRepetition, [string] $RepetitionActionName)
    $p = $Action.properties
    $originalName = if ($RepetitionActionName) { $RepetitionActionName } else { $Action.name }
    $cached = if ($Context.cachedActions) { $Context.cachedActions[$ActionUri] } else { $null }
    $metadataOnly = $IsRepetition -and -not (Test-ScimRepetitionPayloadRequired $ActionType $originalName $p)
    if ($metadataOnly -and $cached -and $cached.status -eq $p.status -and
        ($cached.childRunId -or (Test-ScimRepetitionPayloadRequired $ActionType $originalName @{ status = $p.status; outputs = $cached.outputs }))) {
        $metadataOnly = $false
    }
    $inputValue = $null; $outputValue = $null
    if (-not $metadataOnly) { $inputValue = $p.inputs; $outputValue = $p.outputs }
    $present = @{
        inputs = -not $metadataOnly -and $p -is [System.Collections.IDictionary] -and $p.Contains('inputs')
        outputs = -not $metadataOnly -and $p -is [System.Collections.IDictionary] -and $p.Contains('outputs')
    }
    $presenceSources = @{ inputs = 'InlineProperty'; outputs = 'InlineProperty' }
    $receipts = @{}
    $reused = @{}
    $canReuse = $cached -and $cached.contentAvailability -is [System.Collections.IDictionary] -and
        $cached.status -eq $p.status -and $p.status -in @('Succeeded', 'Failed', 'Cancelled', 'TimedOut', 'Aborted')
    foreach ($kind in @('inputs', 'outputs')) {
        $link = $p["${kind}Link"]
        if ($kind -in $SecureData -or $metadataOnly) { continue }
        if ($link.uri -or ($canReuse -and -not $present[$kind] -and $cached.Contains($kind) -and $cached.contentAvailability[$kind].status -in @('Collected', 'ReusedSanitized'))) {
            if ($canReuse -and $cached.contentAvailability[$kind].status -in @('Collected', 'ReusedSanitized') -and $cached.Contains($kind)) {
                $value = $cached[$kind]
                $reused[$kind] = $true
                $present[$kind] = $true
                $presenceSources[$kind] = 'CachedSanitizedPayload'
                $Context.reusedPayloadCount++
            } else {
                $receipt = @{}
                $value = Invoke-ScimEvidenceRequest $Context $link.uri $false $true -Receipt $receipt
                $receipts[$kind] = $receipt
                $present[$kind] = $receipt.succeeded
                $presenceSources[$kind] = 'ContentLinkResponse'
            }
            if ($kind -eq 'inputs') { $inputValue = $value } else { $outputValue = $value }
        }
    }
    if ($outputValue -is [string] -and $outputValue -match '^\s*[\{\[]') {
        try { $outputValue = ConvertFrom-Json -InputObject $outputValue -AsHashtable -NoEnumerate -ErrorAction Stop } catch { }
    }
    $serialized = @{ inputs = $inputValue; outputs = $outputValue } | ConvertTo-Json -Depth 100 -Compress
    $sensitive = $originalName -match '(?i)(oauth|token|client.?assertion)' -or
        $serialized -match '(?i)(/token\b|/oauth|access_token|refresh_token|id_token|client_secret|client_assertion|grant_type)'
    $metadata = $Action
    if ($metadataOnly) {
        $metadata = @{}
        foreach ($key in $Action.Keys) { $metadata[$key] = $Action[$key] }
        $metadata.properties = @{}
        foreach ($key in $p.Keys) {
            if ($key -notin @('inputs', 'outputs')) { $metadata.properties[$key] = $p[$key] }
        }
    }
    $entry = @{
        name = Protect-ScimValue $Action.name $Context.secrets; status = Protect-ScimValue $p.status $Context.secrets
        code = Protect-ScimValue $p.code $Context.secrets; timing = Get-ScimTiming $p
        semanticResult = 'Unknown'; semanticReason = 'Runtime status alone does not establish test success.'
        evidence = Protect-ScimValue $metadata $Context.secrets
        inputs = $null; outputs = $null; repetitions = @(); securityExclusions = @(); contentAvailability = @{}
        payloadCollection = if ($metadataOnly) { 'MetadataOnlySuccessfulRepetition' } elseif ($IsRepetition) { 'RequiredDiagnosticRepetition' } else { 'TopLevelDiagnosticPayloads' }
    }
    # Discovery uses the raw header only in memory, before the allowlisted evidence is saved.
    $childId = $outputValue.headers.'x-ms-workflow-run-id'
    if (-not $childId -and $canReuse -and -not $metadataOnly) { $childId = $cached.childRunId }
    if ($childId) { $entry.childRunId = Protect-ScimValue ([string]$childId) $Context.secrets }
    if ($sensitive) {
        $entry.inputs = '[OMITTED: sensitive authentication action payload]'
        $entry.outputs = '[OMITTED: sensitive authentication action payload]'
        $safeRetries = @($p.retryHistory | Where-Object { $null -ne $_ } | ForEach-Object {
            Select-ScimMetadataFields $_ @('id', 'status', 'statusCode', 'code', 'startTime', 'endTime', 'trackingId', 'correlation')
        })
        # Inline properties, retries and error details can also contain token endpoint payloads.
        $entry.evidence = Protect-ScimValue @{
            name = $Action.name; properties = @{
                status = $p.status; code = $p.code; startTime = $p.startTime; endTime = $p.endTime
                trackingId = $p.trackingId; clientTrackingId = $p.clientTrackingId
                correlation = $p.correlation; inputsLink = $p.inputsLink; outputsLink = $p.outputsLink
                repetitionIndexes = $p.repetitionIndexes; canResubmit = $p.canResubmit
                retryHistory = $safeRetries
                error = @{ code = $p.error.code; message = '[OMITTED: sensitive authentication action error detail]' }
            }
        } $Context.secrets
    } else {
        $entry.inputs = Protect-ScimValue $inputValue $Context.secrets
        $entry.outputs = Protect-ScimValue $outputValue $Context.secrets
        $semanticPayload = if ($outputValue -is [System.Collections.IDictionary] -and $outputValue.Contains('body')) { $outputValue.body } else { $outputValue }
        if ($semanticPayload -is [System.Collections.IDictionary]) {
            foreach ($field in @('overallResult', 'testResult', 'result')) {
                if ($semanticPayload[$field] -is [string] -and $semanticPayload[$field] -match '^(?i:passed|failed|pass|fail|skipped|not_applicable|not_gallery_ready)$') {
                    $entry.semanticResult = $semanticPayload[$field]
                    $entry.semanticReason = "Explicit $field in the action output, not inferred from runtime status."
                    break
                }
            }
        }
    }
    foreach ($kind in $SecureData) {
        if ($kind -notin @('inputs', 'outputs')) { continue }
        $entry[$kind] = '[EXCLUDED: workflow secureData protection]'
        $entry.securityExclusions += @{ source = $kind; reason = 'Workflow definition intentionally protects this payload with runtimeConfiguration.secureData. Bytes are not claimed or fetched.' }
        if ($entry.evidence.properties -is [System.Collections.IDictionary]) {
            $entry.evidence.properties[$kind] = '[EXCLUDED: workflow secureData protection]'
            $entry.evidence.properties.Remove("${kind}Link")
        }
    }
    foreach ($kind in @('inputs', 'outputs')) {
        $entry.contentAvailability[$kind] = if ($kind -in $SecureData) {
            @{ status = 'SecurityExcluded'; reason = 'Intentionally protected by workflow secureData.' }
        } elseif ($metadataOnly) {
            @{ status = 'NotCollectedByScope'; reason = 'Successful repetition payload is intentionally outside FailureFocused diagnostic scope. All supplied metadata, timing and errors are retained; payload bytes are not claimed.' }
        } elseif ($p.status -in @('Skipped', 'NotStarted') -and -not $present[$kind]) {
            @{ status = 'NotExecuted'; reason = 'Skipped or not-started action has no execution payload; no payload bytes are claimed.' }
        } elseif ($sensitive) {
            @{ status = 'SecurityExcluded'; reason = 'Sensitive authentication action payload is deliberately omitted.' }
        } elseif ($present[$kind]) {
            @{ status = if ($reused[$kind]) { 'ReusedSanitized' } else { 'Collected' }
                presenceSource = $presenceSources[$kind]
                httpStatus = if ($receipts[$kind]) { $receipts[$kind].httpStatus } else { $null }
                reason = if ($reused[$kind]) { 'Sanitized terminal payload reused from the previous report; current ARM metadata was read fresh.' } else { $null } }
        } else {
            @{ status = 'Unavailable'; reason = 'ARM did not provide inline content or a usable content link.' }
        }
        if ($IsRepetition -and $p.status -in @('Failed', 'TimedOut', 'Cancelled', 'Aborted') -and -not $sensitive -and
            $ActionType -in @('Http', 'Workflow', 'Compose') -and $kind -notin $SecureData -and -not $present[$kind]) {
            Add-ScimEvidenceFailure $Context "$ActionUri/$kind" 'Failed or interrupted repetition request/response payload is unavailable within FailureFocused diagnostic scope.'
        }
    }
    if (-not $Repeated -and -not $metadataOnly -and -not $sensitive -and 'outputs' -notin $SecureData -and -not $present.outputs -and
        $ActionType -in @('Http', 'Workflow', 'Compose') -and $p.status -eq 'Succeeded') {
        Add-ScimEvidenceFailure $Context "$ActionUri/outputs" 'Successful data-producing action supplied no readable output evidence.'
    }
    if ($entry.timing.unavailableReason -and $p.status -notin @('Skipped', 'NotStarted')) {
        Add-ScimEvidenceFailure $Context $ActionUri $entry.timing.unavailableReason
    }
    $entry.collectionState = 'InProgress'
    $entry.type = Protect-ScimValue $ActionType $Context.secrets
    if ($Context.activeWorkflow -and $ActionUri -eq $Context.activeActionUri) {
        $Context.activeWorkflow.actions += $entry
    }
    if ($Repeated -and $ActionType -ne 'Until') {
        $repetitionKind = if ($ActionType -eq 'Foreach') { 'scopeRepetitions' } else { 'repetitions' }
        $reps = Get-ScimEvidencePages $Context "$ActionUri/${repetitionKind}?api-version=2022-03-01"
        $entry.repetitionCollection = @{ kind = $repetitionKind }
        foreach ($rep in @($reps | Sort-Object name)) {
            $repUri = "$ActionUri/$repetitionKind/$([uri]::EscapeDataString($rep.name))"
            $props = $rep.properties
            $successfulMetadataOnly = $props -is [System.Collections.IDictionary] -and
                -not (Test-ScimRepetitionPayloadRequired $ActionType $Action.name $props)
            $listed = $props -is [System.Collections.IDictionary] -and (
                $props.status -in @('Skipped', 'NotStarted') -or
                ($successfulMetadataOnly -and $props.startTime -and $props.endTime) -or (
                    $props.status -in @('Succeeded', 'Failed', 'Cancelled', 'TimedOut', 'Aborted') -and
                    $props.startTime -and $props.endTime -and $props.Contains('code') -and
                    ($props.status -ne 'Failed' -or $props.Contains('error')) -and
                    ($props.Contains('inputs') -or $props.inputsLink.uri -or 'inputs' -in $SecureData) -and
                    ($props.Contains('outputs') -or $props.outputsLink.uri -or 'outputs' -in $SecureData)
                ))
            $detail = if ($listed) { $rep } else { Invoke-ScimEvidenceRequest $Context "${repUri}?api-version=2022-03-01" }
            if ($detail) {
                $repetition = Get-ScimActionEvidence $Context $detail $repUri $false $SecureData $ActionType -IsRepetition -RepetitionActionName $Action.name
                $repetition.metadataSource = if ($listed) { 'RepetitionListing' } else { 'RepetitionDetail' }
                $entry.repetitions += $repetition
                $Context.completedRepetitionCount++
                if ($Context.checkpointPath) { Save-ScimCollectionCheckpoint $Context $Context.report $Context.checkpointPath -RepetitionUpdate }
            }
        }
    } elseif ($ActionType -eq 'Until') {
        $entry.iterationCount = Protect-ScimValue $p.iterationCount $Context.secrets
        $entry.repetitionCollection = @{ kind = 'ContainedActionRepetitions'; reason = 'Runtime does not expose scope repetitions for an Until container. Its repeated child actions are collected through their repetitions endpoints.' }
    }
    if ($Context.currentWorkflow -eq 'Orchestrator_Workflow' -and $Action.name -eq 'Final_TestResults' -and -not $sensitive -and $null -ne $outputValue) {
        $Context.finalResult = if ($outputValue.Contains('body')) { $outputValue.body } else { $outputValue }
    }
    $entry.collectionState = 'Completed'
    return $entry
}

function Get-ScimInvocationEvidence {
    param($Entry, [string] $RepetitionPath = '')
    if ($Entry.childRunId) {
        @{ runId = $Entry.childRunId; repetitionPath = $RepetitionPath; evidence = $Entry }
    }
    foreach ($repetition in $Entry.repetitions) {
        $path = if ($RepetitionPath) { "$RepetitionPath/$($repetition.name)" } else { [string]$repetition.name }
        Get-ScimInvocationEvidence $repetition $path
    }
}

function Select-ScimMetadataFields {
    param($Value, [string[]] $Names)
    $selected = @{}
    foreach ($name in $Names) { $selected[$name] = if ($Value -is [System.Collections.IDictionary]) { $Value[$name] } else { $null } }
    return $selected
}

function Add-ScimCachedAction {
    param($Cache, $Entry, [string] $Uri)
    $Cache[$Uri] = $Entry
    $kind = if ($Entry.repetitionCollection.kind -in @('repetitions', 'scopeRepetitions')) { $Entry.repetitionCollection.kind }
        elseif ($Entry.type -eq 'Foreach') { 'scopeRepetitions' } else { 'repetitions' }
    foreach ($repetition in $Entry.repetitions) {
        Add-ScimCachedAction $Cache $repetition "$Uri/$kind/$([uri]::EscapeDataString($repetition.name))"
    }
}

function Get-ScimSanitizedReportSnapshot {
    param($Report, [string[]] $Secrets = @())
    # Workflow headers and each action payload are sanitized when collected.
    # Reprocessing the growing inventory on every checkpoint is quadratic work.
    $snapshot = @{}
    foreach ($key in $Report.Keys) {
        if ($key -ne 'workflows') { $snapshot[$key] = $Report[$key] }
    }
    $snapshot = Protect-ScimValue $snapshot $Secrets
    $snapshot.workflows = $Report.workflows
    return $snapshot
}

function Save-ScimCollectionCheckpoint {
    param($Context, $Report, [string] $Path, [switch] $RepetitionUpdate, [switch] $Force)
    if (-not $Path) { return }
    $completedActions = @($Report.workflows | ForEach-Object { $_.actions | Where-Object collectionState -ne 'InProgress' }).Count
    if (-not $Force -and ($RepetitionUpdate -or $completedActions -ne 1) -and $Context.lastCheckpointUtc -and
        [datetimeoffset]::UtcNow -lt $Context.lastCheckpointUtc.AddSeconds(30)) { return }
    $Report.finalResults = $Context.finalResult
    $Report.evidenceFailures = @($Context.failures)
    $Report.runtime.evidenceRequests = $Context.requestMetrics
    $Report.collection = @{
        status = 'InProgress'; completedActionCount = $completedActions
        completedRepetitionCount = $Context.completedRepetitionCount
        reason = 'Incremental evidence only; collection and readiness evaluation have not finished.'
    }
    $Report.completeness = @{ complete = $false; requiredUnavailableCount = @($Context.failures | Where-Object required).Count }
    $Report.galleryReadiness = @{ ready = $false; status = 'Incomplete'; result = 'INCOMPLETE'; exitCode = 2; reason = $Report.collection.reason }
    $safe = Get-ScimSanitizedReportSnapshot $Report $Context.secrets
    $fullPath = [IO.Path]::GetFullPath($Path)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullPath))
    $pendingPath = "$fullPath.pending"
    [IO.File]::WriteAllText($pendingPath, (ConvertTo-ScimCanonicalJson $safe) + "`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($pendingPath, $fullPath, $true)
    $Context.lastCheckpointUtc = [datetimeoffset]::UtcNow
    Write-Progress -Activity 'Collecting SCIM validation evidence' -Status "$($Report.collection.completedActionCount) actions, $($Context.completedRepetitionCount) repetitions saved; $($Report.workflows.Count) exact workflow runs"
}

function Get-ScimRecordedTiming {
    param($Properties)
    $timing = Get-ScimTiming $Properties
    $state = if (-not $Properties.startTime -and -not $Properties.endTime) { 'Unrecorded' }
        elseif ($Properties.startTime -and -not $Properties.endTime) { 'Open' }
        elseif (-not $Properties.startTime -and $Properties.endTime) { 'MissingStart' }
        elseif ($timing.unavailableReason) { 'Invalid' } else { 'Complete' }
    if ($timing.unavailableReason -like 'Invalid*') { $state = 'Invalid' }
    return @{ timing = $timing; timingState = $state }
}

function Get-ScimAgentEvents {
    param($Context, [string] $Path, [string] $WorkDirectory)
    $result = @{
        status = 'Unavailable'; sourceFileName = $null; unavailableReason = $null
        events = @(); openEventCount = 0; missingTimingCount = 0; invalidEventCount = 0
    }
    if (-not $Path) {
        $result.unavailableReason = 'No agentEventsPath was supplied; historical agent/setup timings were not recorded.'
        Add-ScimEvidenceFailure $Context 'Agent events' $result.unavailableReason $false
        return $result
    }
    try {
        if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path $WorkDirectory $Path }
        $result.sourceFileName = [IO.Path]::GetFileName($Path)
        if ($result.sourceFileName -match '(?i)(parameters|appsettings)') { throw 'Configuration files are not accepted as agent event logs.' }
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if (-not $raw.TrimStart().StartsWith('[')) { throw 'Agent event evidence must be a JSON array.' }
        try { $events = ConvertFrom-Json -InputObject $raw -AsHashtable -NoEnumerate -ErrorAction Stop }
        catch { throw 'Agent event JSON could not be parsed. Supply a valid array of event objects.' }
        $index = 0
        foreach ($event in $events) {
            $index++
            if ($event -isnot [System.Collections.IDictionary]) {
                $result.events += @{
                    index = $index; name = $null; kind = $null; parentName = $null; status = $null; details = $null
                    timing = Get-ScimTiming @{}; timingState = 'Invalid'
                    unavailableReason = 'Recorded event is not a JSON object.'
                }
                $result.invalidEventCount++
                continue
            }
            $record = Select-ScimMetadataFields $event @('name', 'kind', 'parentName', 'status', 'details')
            $record.index = $index
            $recorded = Get-ScimRecordedTiming $event
            $record.timing = $recorded.timing
            $record.timingState = $recorded.timingState
            $record.unavailableReason = if (-not $event.name -or -not $event.kind -or -not $event.status) {
                'One or more explicit event name, kind or status fields were not recorded.'
            } else { $record.timing.unavailableReason }
            switch ($record.timingState) {
                'Open' { $result.openEventCount++ }
                'Invalid' { $result.invalidEventCount++ }
                { $_ -in @('Unrecorded', 'MissingStart') } { $result.missingTimingCount++ }
            }
            $result.events += Protect-ScimValue $record $Context.secrets
        }
        if (-not $result.events.Count) { throw 'Agent event evidence contains no recorded events.' }
        $partial = $result.openEventCount -gt 0 -or $result.missingTimingCount -gt 0 -or $result.invalidEventCount -gt 0 -or
            @($result.events | Where-Object unavailableReason).Count -gt 0
        $result.status = if ($partial) { 'Partial' } else { 'Available' }
        if ($partial) {
            $result.unavailableReason = 'Some recorded agent events are open, invalid or missing fields/timings; no timestamps were invented.'
            Add-ScimEvidenceFailure $Context 'Agent events' $result.unavailableReason $false
        }
    } catch {
        $result.status = 'Unavailable'
        $result.unavailableReason = Protect-ScimText $_.Exception.Message $Context.secrets
        Add-ScimEvidenceFailure $Context 'Agent events' $result.unavailableReason $false
    }
    return $result
}

function Get-ScimSemanticTests {
    param($FinalResult, $Applicability, $Workflows, [string[]] $Methods = @())
    foreach ($test in @($FinalResult.testResults | Sort-Object testName)) {
        if ($null -eq $test) { continue }
        $app = $Applicability[$test.testName]
        $testReason = if ($test.applicabilityReason) { $test.applicabilityReason } elseif ($test.reason) { $test.reason } else { $null }
        $result = [string]$test.testResult
        $method = if ($test.testName -eq 'Validate_Credentials_Test' -or $test.testName -match '(?i)oauth') { 'OAuth2ClientCredentials' }
            elseif ($test.testName -match '(?i)(federat|workload.?identity|(^|_)WIF(_|$))') { 'WorkloadIdentityFederation' }
            elseif ($test.testName -match '(?i)bearer.*connectivity|connectivity.*bearer') { 'Bearer' } else { $null }
        if (-not $testReason -and $result -match '^(?i:NOT_APPLICABLE)\s*-\s*(.+)$') { $testReason = $Matches[1] }
        $excluded = ($null -ne $app -and $app.applicable -eq $false -and -not [string]::IsNullOrWhiteSpace($app.reason)) -or
            ($test.applicable -eq $false -and $result -match '^(?i:NOT_APPLICABLE)(?:\s*-|$)' -and -not [string]::IsNullOrWhiteSpace($testReason)) -or
            ($method -and $Methods.Count -gt 0 -and $method -notin $Methods -and $result -match '^(?i:NOT_APPLICABLE)(?:\s*-|$)' -and $testReason)
        $passed = $result -match '^(?i:pass|passed|success|succeeded|true)(?:\s*\([^)]*\))?$'
        if ($method -and $Methods.Count -gt 0) {
            $excluded = $method -notin $Methods
            if ($excluded) { $testReason = 'Authentication method was not selected; recorded runtime result is retained as historical evidence.' }
        }
        $warningAllowed = $test.testCategory -match '(?i)(^|/)OptionalSuccess$' -and $result -match '^(?i:WARNING)\b'
        $timings = @($Workflows | ForEach-Object {
            $workflowName = $_.name
            $_.actions | Where-Object {
                (($_.name -replace '[^a-zA-Z0-9]', '') -eq ($test.testName -replace '[^a-zA-Z0-9]', ''))
            } | ForEach-Object { @{ workflow = $workflowName; action = $_.name; timing = $_.timing; status = $_.status } }
        })
        @{
            name = $test.testName; category = $test.testCategory; semanticResult = $result
            applicable = -not $excluded; applicabilityReason = if ($excluded) { if ($method) { $testReason } elseif ($app.reason) { $app.reason } else { $testReason } } else { 'Applicable unless explicitly excluded with a reason.' }
            passing = (-not $excluded) -and $passed; evidence = $test
            authenticationMethod = $method; nonBlockingWarning = [bool]$warningAllowed
            classification = if ($excluded) { 'NotApplicable' } elseif ($passed) { 'Passed' } elseif ($warningAllowed) { 'Warning' } elseif ($result -match '^(?i:FAILED|FAIL)\b') { 'Failed' } else { 'Unknown' }
            scopeTimings = $timings
            timingUnavailableReason = if (-not $timings.Count) { 'No exact test-name scope match; use the workflow action timing inventory.' } else { $null }
        }
    }
}

function New-ScimValidationReport {
    param(
        [string] $SubscriptionId, [string] $ResourceGroupName, [string] $LogicAppName,
        [string] $OrchestratorRunId, [string] $AgentPath, [string] $WorkflowDirectory,
        [System.Collections.IDictionary] $Metadata = @{}, [string[]] $KnownSecrets = @(),
        [scriptblock] $Request, [System.Collections.IDictionary] $RuntimeMetadata = @{},
        [string] $WorkDirectory = (Get-Location).Path, [System.Collections.IDictionary] $AuthenticationState,
        [System.Collections.IDictionary] $PreviousReport, [string] $CheckpointPath
    )
    foreach ($section in @('environment', 'harness', 'preflight')) {
        if (-not $Metadata[$section]) { $Metadata[$section] = @{} }
    }
    $methods = if ($Metadata.supportedAuthenticationMethods) { @($Metadata.supportedAuthenticationMethods) } else { @($Metadata.authenticationMethods) }
    $ctx = @{
        request = $Request; secrets = @($KnownSecrets) + @($Metadata.knownSecrets)
        failures = [System.Collections.Generic.List[object]]::new(); finalResult = $null
        securityExclusions = [System.Collections.Generic.List[object]]::new()
        cachedActions = @{}; reusedPayloadCount = 0
        requestMetricsEnabled = [bool]$CheckpointPath -or [bool]$AuthenticationState; requestMetrics = @{}
        completedRepetitionCount = 0; checkpointPath = $CheckpointPath; lastCheckpointUtc = $null
    }
    if ($AuthenticationState) {
        foreach ($literal in @($KnownSecrets) + @($Metadata.knownSecrets)) {
            if ($literal -and -not $AuthenticationState.secretLiterals.Contains($literal)) { $AuthenticationState.secretLiterals.Add($literal) }
        }
        $ctx.secrets = $AuthenticationState.secretLiterals
    }
    $report = @{
        schema = 'scim.validation-run-details'; schemaVersion = '1.1.0'; purpose = 'production-validation'
        orchestratorRunId = if ($OrchestratorRunId) { $OrchestratorRunId } else { $null }
        fullRun = @{
            status = if ($OrchestratorRunId) { 'Unavailable' } else { 'NotExecuted' }
            timing = Get-ScimTiming $(if ($OrchestratorRunId) { @{} } else { $Metadata.preflight })
            unavailableReason = if ($OrchestratorRunId) { 'An execution ID was supplied, but Azure Orchestrator run evidence has not been obtained.' } else { $null }
        }
        provenance = @{ agent = $null; sourceVersion = @{ value = $null; sha256 = $null; fileName = 'VERSION'; scope = 'Local reporting source only; not the deployed historical run version'; unavailableReason = $null }; sourceGit = @{ revision = $null; dirty = $null; unavailableReason = $null }; workflows = @() }
        environment = @{}; runtime = $RuntimeMetadata
        harness = @{}; authentication = @{ selectedMethods = $methods; applicability = $Metadata.applicability; policy = 'Every selected supported authentication method must pass (AND), including static-token connectivity. At least one selected gallery-eligible method is required.' }
        workflows = @(); tests = @(); finalResults = $null; provisioningLogs = @(); childRunAssociations = @()
        suppliedSource = @{ attribution = 'Caller-supplied; not independently verified'; metadata = $null }
        deploymentOverlay = @{ attribution = 'Caller-supplied identifiers/hashes; no deployment equivalence is asserted'; metadata = $null }
        evidenceFailures = @(); completeness = @{}; galleryReadiness = @{}
        redaction = @{ policyVersion = '1'; rawCredentialsPersisted = $false; tokenPayloads = 'Omitted'; headers = 'Allowlisted'; urlQueries = 'All values omitted' }
        diagnosticScope = @{
            name = 'FailureFocused'
            metadata = 'Every action and repetition, including all supplied timing, status, errors and retry metadata; no sampling or truncation.'
            payloads = 'Top-level actions and failed, timed-out, cancelled or aborted repetitions; successful semantic-result producers and child-workflow calls remain included.'
            successfulRepeatedPollPayloads = 'Intentionally not collected. NotCollectedByScope is not a payload-download failure and does not claim payload completeness.'
        }
    }
    $report.historicalRun = @{ attribution = 'Caller-recorded deployed-run claims; not inferred from current source'; metadata = $null; unavailableReason = 'Historical deployed version and authentication policy were not recorded.' }
    if ($Metadata.historicalRun) {
        $report.historicalRun.metadata = Select-ScimMetadataFields $Metadata.historicalRun @('version', 'authenticationPolicy', 'selectedMethods', 'description')
        if ($Metadata.historicalRun.sourceVersion) {
            $report.historicalRun.metadata.sourceVersion = Select-ScimMetadataFields $Metadata.historicalRun.sourceVersion @('value', 'sha256')
        }
        $report.historicalRun.unavailableReason = $null
    } elseif ($PreviousReport.historicalRun.metadata) {
        $report.historicalRun = $PreviousReport.historicalRun
    }
    try {
        $versionPath = Join-Path $WorkflowDirectory 'VERSION'
        $sourceVersion = (Get-Content -LiteralPath $versionPath -Raw -ErrorAction Stop).Trim()
        if ($sourceVersion -notmatch '^\d+\.\d+(?:\.\d+)?$') { throw 'VERSION must contain a numeric release version.' }
        $report.provenance.sourceVersion.value = $sourceVersion
        $report.provenance.sourceVersion.sha256 = (Get-FileHash -LiteralPath $versionPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        $report.provenance.sourceVersion.unavailableReason = 'Local VERSION is missing, unreadable, or invalid.'
        Add-ScimEvidenceFailure $ctx 'VERSION provenance' $report.provenance.sourceVersion.unavailableReason
    }
    $report.provenance.comparison = @{
        deployedVersionMatchesSource = if ($report.historicalRun.metadata.version -and $report.provenance.sourceVersion.value) { $report.historicalRun.metadata.version -eq $report.provenance.sourceVersion.value } else { $null }
        reason = 'Local VERSION, agent and workflow hashes describe current source, not the definitions or authentication policy deployed for this run.'
    }
    $agentWindow = if ($Metadata.agentRun) { $Metadata.agentRun } else { @{} }
    $recordedAgentWindow = Get-ScimRecordedTiming $agentWindow
    $report.agentRun = @{
        status = $agentWindow.status; timing = $recordedAgentWindow.timing; timingState = $recordedAgentWindow.timingState
        statusUnavailableReason = if (-not $agentWindow.status) { 'Agent run status was not explicitly recorded.' } else { $null }
        window = 'Explicit agent/setup-to-cleanup window; separate from Azure Orchestrator fullRun timing.'
    }
    $report.agentEvents = Get-ScimAgentEvents $ctx $Metadata.agentEventsPath $WorkDirectory
    if ($Metadata.source) { $report.suppliedSource.metadata = Select-ScimMetadataFields $Metadata.source @('repositoryUrl', 'revision', 'branch', 'dirty', 'description') }
    if ($Metadata.deploymentOverlay) {
        $report.deploymentOverlay.metadata = Select-ScimMetadataFields $Metadata.deploymentOverlay @('name', 'revision', 'sha256', 'description')
        $report.deploymentOverlay.metadata.workflowHashes = @($Metadata.deploymentOverlay.workflowHashes | ForEach-Object {
            Select-ScimMetadataFields $_ @('name', 'sha256')
        })
    }
    foreach ($field in @('tenantId', 'subscriptionId', 'resourceGroupName', 'logicAppName', 'managedIdentity', 'entraApplication', 'servicePrincipal', 'provisioningJob', 'endpoint', 'operatorIdentity')) {
        $report.environment[$field] = @{ value = $Metadata.environment[$field]; unavailableReason = if ($null -eq $Metadata.environment[$field]) { 'Not supplied or obtainable with the selected evidence permissions.' } else { $null } }
    }
    foreach ($pair in @(@('subscriptionId', $SubscriptionId), @('resourceGroupName', $ResourceGroupName), @('logicAppName', $LogicAppName))) {
        if ($pair[1]) { $report.environment[$pair[0]] = @{ value = $pair[1]; unavailableReason = $null } }
    }
    foreach ($field in @('name', 'version', 'model', 'reasoning', 'context')) {
        $report.harness[$field] = @{ value = $Metadata.harness[$field]; unavailableReason = if ($null -eq $Metadata.harness[$field]) { 'Not explicitly supplied by caller; hidden host data is not inspected.' } else { $null } }
    }
    try {
        $agent = Get-Item -LiteralPath $AgentPath -ErrorAction Stop
        $report.provenance.agent = @{ fileName = $agent.Name; sha256 = (Get-FileHash -LiteralPath $agent.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        $report.provenance.agent.sourceVersion = $report.provenance.sourceVersion.value
        $report.provenance.agent.versionSource = 'VERSION; local source only'
        $rev = & git -C $agent.DirectoryName rev-parse HEAD 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Agent directory is not an accessible Git worktree.' }
        $dirty = @(& git -C $agent.DirectoryName status --porcelain --untracked-files=normal 2>$null)
        if ($LASTEXITCODE -ne 0) { throw 'Git dirty state could not be read.' }
        $report.provenance.sourceGit.revision = [string]$rev
        $report.provenance.sourceGit.dirty = $dirty.Count -gt 0
    } catch {
        $report.provenance.sourceGit.unavailableReason = $_.Exception.Message
        Add-ScimEvidenceFailure $ctx 'Agent/source provenance' $_.Exception.Message
    }
    $definitions = @{}
    $expectedTests = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $WorkflowDirectory -Filter '*_Workflow.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $wf = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            $definitions[$file.BaseName] = @(Get-ScimDefinitionActions $wf.definition.actions)
            if ($file.BaseName -eq 'Orchestrator_Workflow') {
                $expectedTests = @($wf.definition.actions.Final_TestResults.inputs.testResults | ForEach-Object testName | Where-Object { $_ -and $_ -notmatch '^@' })
            }
            $report.provenance.workflows += @{ name = $file.BaseName; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); source = 'Local definition; not a claim of deployed content equivalence' }
        } catch { Add-ScimEvidenceFailure $ctx "Workflow definition $($file.Name)" $_.Exception.Message }
    }
    if (-not $definitions.Count) { Add-ScimEvidenceFailure $ctx 'Workflow definitions' 'No local workflow definitions were found.' }
    $base = "https://management.azure.com/subscriptions/$([uri]::EscapeDataString($SubscriptionId))/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))/providers/Microsoft.Web/sites/$([uri]::EscapeDataString($LogicAppName))"
    $api = "$base/hostruntime/runtime/webhooks/workflow/api/management"
    if ($PreviousReport) {
        if ($PreviousReport.schema -ne 'scim.validation-run-details' -or $PreviousReport.orchestratorRunId -ne $OrchestratorRunId -or
            $PreviousReport.environment.subscriptionId.value -ne $SubscriptionId -or
            $PreviousReport.environment.resourceGroupName.value -ne $ResourceGroupName -or
            $PreviousReport.environment.logicAppName.value -ne $LogicAppName) {
            throw 'Resume report does not match the requested schema, root run and Azure site.'
        }
        foreach ($previousWorkflow in $PreviousReport.workflows) {
            if ($previousWorkflow.status -notin @('Succeeded', 'Failed', 'Cancelled', 'TimedOut', 'Aborted')) { continue }
            $previousUri = "$api/workflows/$([uri]::EscapeDataString($previousWorkflow.name))/runs/$([uri]::EscapeDataString($previousWorkflow.runId))"
            foreach ($previousAction in $previousWorkflow.actions) {
                Add-ScimCachedAction $ctx.cachedActions $previousAction "$previousUri/actions/$([uri]::EscapeDataString($previousAction.name))"
            }
        }
    }
    $ctx.report = $report
    Save-ScimCollectionCheckpoint $ctx $report $CheckpointPath -Force
    if ($OrchestratorRunId) {
        $site = Invoke-ScimEvidenceRequest $ctx "${base}?api-version=2022-03-01"
        if ($site) { $report.environment.managedIdentity = @{ value = $site.identity; unavailableReason = if (-not $site.identity) { 'Site has no managed identity.' } else { $null } } }
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@{ name = 'Orchestrator_Workflow'; runId = $OrchestratorRunId; discovery = 'Explicit OrchestratorRunId' })
        foreach ($supplied in @($Metadata.workflowRuns)) {
            if ($null -eq $supplied) { continue }
            if (-not $supplied.workflowName -or -not $supplied.runId) {
                Add-ScimEvidenceFailure $ctx 'Supplied workflowRuns' 'Each supplied workflow run requires workflowName and runId.'
                continue
            }
            $queue.Enqueue(@{ name = [string]$supplied.workflowName; runId = [string]$supplied.runId; discovery = 'Caller-supplied exact run ID' })
            $association = Select-ScimMetadataFields $supplied @('workflowName', 'runId', 'parentWorkflowName', 'parentRunId', 'parentActionName', 'repetitionName')
            $association.attribution = 'Caller-supplied exact association; not inferred from hidden payloads'
            $report.childRunAssociations += $association
        }
        $seenRuns = [System.Collections.Generic.HashSet[string]]::new()
        $seenCorrelations = [System.Collections.Generic.HashSet[string]]::new()
        while ($queue.Count) {
            $item = $queue.Dequeue()
            if (-not $seenRuns.Add("$($item.name)/$($item.runId)")) { continue }
            $runUri = "$api/workflows/$([uri]::EscapeDataString($item.name))/runs/$([uri]::EscapeDataString($item.runId))"
            $run = Invoke-ScimEvidenceRequest $ctx "${runUri}?api-version=2022-03-01"
            if (-not $run) { continue }
            $ctx.currentWorkflow = $item.name
            $wfReport = @{
                name = $item.name; runId = $item.runId; status = $run.properties.status
                discovery = $item.discovery
                timing = Get-ScimTiming $run.properties; run = Protect-ScimValue $run $ctx.secrets
                triggers = @(); actions = @(); scopes = @()
            }
            $wfReport = Protect-ScimValue $wfReport $ctx.secrets
            $report.workflows += $wfReport
            $ctx.activeWorkflow = $wfReport
            if ($wfReport.timing.unavailableReason) { Add-ScimEvidenceFailure $ctx $runUri $wfReport.timing.unavailableReason }
            if ($item.name -eq 'Orchestrator_Workflow') { $report.fullRun = @{ status = $wfReport.status; timing = $wfReport.timing } }
            # The run header identifies the exact trigger history; never query an unrelated latest history.
            if ($run.properties.trigger.name) {
                $trigger = $run.properties.trigger
                $wfReport.triggers = @(Get-ScimActionEvidence $ctx @{ name = $trigger.name; properties = $trigger } "$runUri/trigger")
                if ($trigger.originHistoryName) {
                    $triggerUri = "$api/workflows/$([uri]::EscapeDataString($item.name))/triggers/$([uri]::EscapeDataString($trigger.name))/histories/$([uri]::EscapeDataString($trigger.originHistoryName))"
                    $history = Invoke-ScimEvidenceRequest $ctx "${triggerUri}?api-version=2022-03-01"
                    if ($history) { $wfReport.triggers += Get-ScimActionEvidence $ctx $history $triggerUri }
                }
            } else { Add-ScimEvidenceFailure $ctx "$runUri/trigger" 'Run header did not supply trigger evidence.' }
            $actions = Get-ScimEvidencePages $ctx "$runUri/actions?api-version=2022-03-01"
            if (-not $actions.Count) { Add-ScimEvidenceFailure $ctx "$runUri/actions" 'No action evidence was returned.' }
            foreach ($action in @($actions | Sort-Object name)) {
                $definition = @($definitions[$item.name] | Where-Object name -eq $action.name) | Select-Object -First 1
                $repeated = $definition.repeated -or $definition.type -eq 'Foreach' -or [bool]$action.properties.repetitionIndexes
                $actionUri = "$runUri/actions/$([uri]::EscapeDataString($action.name))"
                $ctx.activeActionUri = $actionUri
                $entry = Get-ScimActionEvidence $ctx $action $actionUri $repeated $definition.secureData $definition.type
                $entry.parentScope = Protect-ScimValue $definition.parent $ctx.secrets
                $ctx.activeActionUri = $null
                Save-ScimCollectionCheckpoint $ctx $report $CheckpointPath
                if ($definition.type -eq 'Scope') { $wfReport.scopes += @{ name = $entry.name; status = $entry.status; timing = $entry.timing; semanticResult = $entry.semanticResult; semanticReason = $entry.semanticReason } }
                if ($definition.type -eq 'Workflow') {
                    $childName = if ($definition.targetWorkflow) { ([string]$definition.targetWorkflow -split '/')[-1] } else { $action.name -replace '^Call_', '' }
                    $invocations = @(Get-ScimInvocationEvidence $entry)
                    foreach ($invocation in $invocations) {
                        $queue.Enqueue(@{ name = $childName; runId = $invocation.runId; discovery = 'Exact Workflow action output run-ID header' })
                        $report.childRunAssociations += @{
                            workflowName = $childName; runId = $invocation.runId; parentWorkflowName = $item.name
                            parentRunId = $item.runId; parentActionName = $action.name; repetitionName = $invocation.repetitionPath
                            attribution = 'Exact Workflow action output run-ID header'
                        }
                    }
                    if (-not $invocations.Count -and 'outputs' -in $definition.secureData -and $action.properties.status -ne 'Skipped') {
                        $ctx.securityExclusions.Add(@{
                            source = $actionUri; reason = 'Workflow call outputs, including a possible child run-ID header, are intentionally secured. No exact child mapping is invented.'
                        })
                        $correlation = if ($action.properties.correlation.clientTrackingId) { $action.properties.correlation.clientTrackingId } else { $run.properties.correlation.clientTrackingId }
                        if ($correlation -and $seenCorrelations.Add("$childName/$correlation")) {
                            $filter = [uri]::EscapeDataString("ClientTrackingId eq '$(([string]$correlation).Replace("'", "''"))'")
                            $childRunsUri = "$api/workflows/$([uri]::EscapeDataString($childName))/runs?api-version=2022-03-01&`$filter=$filter"
                            $correlatedRuns = Get-ScimEvidencePages $ctx $childRunsUri $false
                            foreach ($candidate in $correlatedRuns) {
                                if ($candidate.name -and $candidate.properties.correlation.clientTrackingId -eq $correlation) {
                                    $queue.Enqueue(@{ name = $childName; runId = [string]$candidate.name; discovery = 'Correlation-only inventory; not an exact parent-action association' })
                                }
                            }
                        }
                    } elseif (-not $invocations.Count -and $action.properties.status -notin @('Skipped', 'NotStarted')) {
                        Add-ScimEvidenceFailure $ctx $actionUri 'Child workflow run ID was not present in the call outputs.'
                    }
                }
            }
            Save-ScimCollectionCheckpoint $ctx $report $CheckpointPath -Force
        }
        foreach ($expected in @('Orchestrator_Workflow', 'Initialization_Workflow', 'UserTests_Workflow', 'GroupTests_Workflow', 'SCIMTests_Workflow')) {
            if (-not @($report.workflows | Where-Object name -eq $expected).Count) { Add-ScimEvidenceFailure $ctx $expected 'Required workflow run was not discovered or could not be read.' }
        }
    } else {
        $report.fullRun.status = 'Blocked'
        $report.fullRun.reason = $Metadata.preflight.reason
        Add-ScimEvidenceFailure $ctx 'Execution' 'No Orchestrator run ID supplied; no execution is claimed.'
    }
    $report.finalResults = $ctx.finalResult
    if (-not $methods.Count) {
        $methods = if ($ctx.finalResult.supportedAuthenticationMethods) { @($ctx.finalResult.supportedAuthenticationMethods) } else { @($ctx.finalResult.authenticationModelResult.supportedAuthenticationMethods) }
        $report.authentication.selectedMethods = $methods
    }
    $transport = if ($Metadata.scimAuthenticationMethod) { $Metadata.scimAuthenticationMethod } else { $ctx.finalResult.scimAuthenticationMethod }
    $report.authentication.scimRequestTransport = @{
        value = $transport
        unavailableReason = if (-not $transport) { 'Direct SCIM request transport was not supplied by caller or Final_TestResults.' } else { $null }
    }
    $report.authentication.selectionSource = if ($Metadata.supportedAuthenticationMethods -or $Metadata.authenticationMethods) { 'Caller-supplied selection for this assessment' } else { 'Recorded Final_TestResults' }
    $report.authentication.recordedSelectedMethods = if ($ctx.finalResult.supportedAuthenticationMethods) { @($ctx.finalResult.supportedAuthenticationMethods) } else { @($ctx.finalResult.authenticationModelResult.supportedAuthenticationMethods) }
    $report.authentication.selectionMismatch = $report.authentication.recordedSelectedMethods.Count -gt 0 -and
        (($methods | Sort-Object -Unique) -join ',') -ne (($report.authentication.recordedSelectedMethods | Sort-Object -Unique) -join ',')
    if ($report.authentication.selectionMismatch) {
        Add-ScimEvidenceFailure $ctx 'Authentication selection provenance' 'Caller selection differs from recorded executed selection; reconcile the evidence rather than waive a selected method.'
    }
    if (-not $methods.Count) { Add-ScimEvidenceFailure $ctx 'Authentication selection' 'Selected authentication methods were not supplied by caller or Final_TestResults.' }
    if (-not $ctx.finalResult.testResults) { Add-ScimEvidenceFailure $ctx 'Final_TestResults' 'Semantic test results were not available.' }
    $applicability = if ($Metadata.applicability) { $Metadata.applicability } else { @{} }
    $report.tests = @(Get-ScimSemanticTests $ctx.finalResult $applicability $report.workflows $methods)
    $report.testSummary = @{
        total = $report.tests.Count
        passed = @($report.tests | Where-Object classification -eq 'Passed').Count
        warnings = @($report.tests | Where-Object classification -eq 'Warning').Count
        failed = @($report.tests | Where-Object classification -eq 'Failed').Count
        notApplicable = @($report.tests | Where-Object classification -eq 'NotApplicable').Count
        unknown = @($report.tests | Where-Object classification -eq 'Unknown').Count
    }
    foreach ($expected in $expectedTests) {
        if (@($report.tests | Where-Object name -eq $expected).Count -ne 1) {
            Add-ScimEvidenceFailure $ctx "Semantic test $expected" 'Expected exactly one result from the local Orchestrator definition; result is missing or duplicated.'
        }
    }
    foreach ($workflow in $report.workflows) {
        foreach ($scope in $workflow.scopes) {
            $semantic = @($report.tests | Where-Object { ($_.name -replace '[^a-zA-Z0-9]', '') -eq ($scope.name -replace '[^a-zA-Z0-9]', '') })
            if ($semantic.Count -eq 1) { $scope.semanticResult = Protect-ScimValue $semantic[0].semanticResult $ctx.secrets; $scope.semanticReason = 'Matched exact normalized test name in Final_TestResults.' }
        }
    }
    if ($Metadata.provisioningLogPath) {
        try {
            if ([IO.Path]::GetFileName($Metadata.provisioningLogPath) -match '(?i)(parameters|appsettings).*\.json$') { throw 'Configuration files are not accepted as provisioning logs.' }
            $log = Get-Content -LiteralPath $Metadata.provisioningLogPath -Raw -ErrorAction Stop
            $report.provisioningLogs = @(@{ fileName = [IO.Path]::GetFileName($Metadata.provisioningLogPath); content = Protect-ScimValue $log $ctx.secrets })
        } catch { Add-ScimEvidenceFailure $ctx 'Supplied provisioning log' $_.Exception.Message }
    } else {
        Add-ScimEvidenceFailure $ctx 'Provisioning logs' 'No provisioning log was supplied; this optional source was not collected.' $false
    }
    $report.evidenceFailures = @($ctx.failures)
    $missing = @($ctx.failures | Where-Object required).Count
    $report.securityExclusions = @($ctx.securityExclusions)
    $securedPayloadCount = @($report.workflows | ForEach-Object { $_.actions | ForEach-Object { $_.securityExclusions } }).Count
    $report.completeness = @{
        complete = $missing -eq 0; requiredUnavailableCount = $missing
        optionalUnavailableCount = @($ctx.failures | Where-Object { -not $_.required }).Count
        securityExcludedCount = $ctx.securityExclusions.Count + $securedPayloadCount
        scope = 'Complete within FailureFocused diagnostic scope means all required metadata/timings and in-scope payload evidence was collected. Successful repeated-poll payloads marked NotCollectedByScope are intentionally not collected. Security exclusions are separate; completeness never claims every payload or hidden parent-action association.'
    }
    $applicableTests = @($report.tests | Where-Object applicable)
    $authTests = @($report.tests | Where-Object authenticationMethod)
    $report.authentication.bearerConnectivity = $ctx.finalResult.BearerConnectivityTestOutputs
    if ($ctx.finalResult.BearerConnectivityTestOutputs -and -not @($authTests | Where-Object authenticationMethod -eq 'Bearer').Count) {
        $bearerResult = $ctx.finalResult.BearerConnectivityTestOutputs
        $bearerSemantic = if ($bearerResult.overallResult) { $bearerResult.overallResult } else { $bearerResult.result }
        $authTests += @(Get-ScimSemanticTests @{ testResults = @(@{
            testName = 'Bearer_Connectivity_Test'; testCategory = 'Authentication'; testResult = $bearerSemantic
            details = $bearerResult
        }) } @{} $report.workflows $methods)
    }
    $failedTests = @($applicableTests | Where-Object { -not $_.passing -and -not $_.nonBlockingWarning -and $_ -notin $authTests })
    $eligibleMethods = @('OAuth2ClientCredentials', 'WorkloadIdentityFederation')
    $methodResults = @(
        foreach ($method in @($methods | Sort-Object -Unique)) {
            $results = @($authTests | Where-Object authenticationMethod -eq $method)
            $supported = $method -in (@('Bearer') + $eligibleMethods)
            $passing = $supported -and $results.Count -gt 0 -and @($results | Where-Object { -not $_.applicable -or -not $_.passing }).Count -eq 0
            if ($supported -and (-not $results.Count -or @($results | Where-Object { $_.classification -in @('Unknown', 'NotApplicable') -or $_.semanticResult -match '(?i)(NOT_APPLICABLE|MISSING|NOT_CONFIGURED|BLOCKED|CREDENTIAL)' }).Count)) {
                Add-ScimEvidenceFailure $ctx "Selected authentication method $method" 'Selected method lacks a conclusive required result or required credentials; it cannot be waived as not applicable.'
            }
            @{ method = $method; eligible = $method -in $eligibleMethods; supported = $supported; passing = $passing; resultCount = $results.Count
                reason = if ($passing) { 'All selected-method tests passed.' } elseif (-not $supported) { 'This selected method is unsupported.' } else { 'Every selected method, including static-token connectivity, must pass; aggregate success cannot override this result.' } }
        }
    )
    $galleryAuthPass = @($methodResults | Where-Object eligible).Count -gt 0 -and @($methodResults | Where-Object { -not $_.passing }).Count -eq 0
    $report.authentication.methodResults = $methodResults
    $report.authentication.semanticResult = $ctx.finalResult.authenticationModelResult
    if ($null -eq $ctx.finalResult.authenticationModelResult) {
        Add-ScimEvidenceFailure $ctx 'Authentication semantics' 'Final_TestResults did not supply authenticationModelResult.'
    }
    $missing = @($ctx.failures | Where-Object required).Count
    $report.evidenceFailures = @($ctx.failures)
    $report.completeness.complete = $missing -eq 0
    $report.completeness.requiredUnavailableCount = $missing
    $runtimeFailures = @($report.workflows | Where-Object { $_.name -eq 'Orchestrator_Workflow' -and $_.status -ne 'Succeeded' })
    $overallPassed = [string]$ctx.finalResult.overallResult -match '^(?i:pass|passed|success|succeeded|true)$'
    $authOverall = if ($ctx.finalResult.authenticationModelResult -is [System.Collections.IDictionary]) {
        if ($ctx.finalResult.authenticationModelResult.overallResult) { $ctx.finalResult.authenticationModelResult.overallResult } else { $ctx.finalResult.authenticationModelResult.result }
    } else { $ctx.finalResult.authenticationModelResult }
    $authPassed = [string]$authOverall -match '^(?i:pass|passed|success|succeeded|true)$'
    $report.authentication.recordedAggregateResult = $authOverall
    $report.authentication.recordedPolicy = if ($ctx.finalResult.authenticationPolicy) { $ctx.finalResult.authenticationPolicy } else { $ctx.finalResult.authenticationModelResult.authenticationPolicy }
    $report.authentication.aggregatePolicyMismatch = $authPassed -and -not $galleryAuthPass
    $report.provenance.executedVersion = @{
        value = if ($ctx.finalResult.LogicAppVersion) { $ctx.finalResult.LogicAppVersion } elseif ($ctx.finalResult.logicAppVersion) { $ctx.finalResult.logicAppVersion } else { $report.historicalRun.metadata.version }
        attribution = if ($ctx.finalResult.LogicAppVersion) { 'Recorded Final_TestResults output' } else { 'Caller historicalRun metadata, when supplied; never inferred from local VERSION' }
    }
    if ($report.provenance.executedVersion.value) {
        $report.provenance.comparison.deployedVersionMatchesSource = $report.provenance.executedVersion.value -eq $report.provenance.sourceVersion.value
    }
    $coreTests = @($applicableTests | Where-Object { $_ -notin $authTests })
    $ready = $missing -eq 0 -and $overallPassed -and $galleryAuthPass -and $authPassed -and $coreTests.Count -gt 0 -and $failedTests.Count -eq 0 -and $runtimeFailures.Count -eq 0
    $report.galleryReadiness = @{
        ready = $ready; status = if ($missing) { 'Incomplete' } elseif ($ready) { 'Ready' } else { 'NotReady' }
        result = if ($missing) { 'INCOMPLETE' } elseif ($ready) { 'GALLERY_READY' } else { 'NOT_GALLERY_READY' }
        reason = if ($missing) { 'Required evidence is unavailable; do not claim gallery readiness.' } elseif ($ready) { 'Core tests and every selected authentication method passed, including at least one gallery-eligible method.' } else { 'Core validation or a selected authentication method has not passed. Static-token connectivity alone is not gallery-ready.' }
        failedOrUnknownApplicableTests = @($failedTests.name)
        nonBlockingWarningTests = @($report.tests | Where-Object nonBlockingWarning | ForEach-Object name)
        exitCode = if ($missing) { 2 } elseif ($ready) { 0 } else { 1 }
    }
    if ($AuthenticationState) {
        $report.runtime.armTokenRefreshCount = $AuthenticationState.refreshCount
        $report.runtime.arm401RetryCount = $AuthenticationState.retry401Count
    }
    $report.resume = @{
        requested = [bool]$PreviousReport; reusedPayloadCount = $ctx.reusedPayloadCount
        policy = 'Only available sanitized terminal-action payloads are reused. ARM run/action/repetition metadata is read fresh and all failures are recomputed.'
    }
    $report.collection = @{ status = 'Completed'; completedActionCount = @($report.workflows | ForEach-Object { $_.actions }).Count }
    if ($ctx.requestMetricsEnabled) { $report.runtime.evidenceRequests = $ctx.requestMetrics }
    if ($CheckpointPath) { Write-Progress -Activity 'Collecting SCIM validation evidence' -Completed }
    return Get-ScimSanitizedReportSnapshot $report $ctx.secrets
}

function Complete-ScimValidationReport {
    param([Parameter(Mandatory)][string] $ReportPath)
    $report = Get-Content -LiteralPath $ReportPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($report.schema -ne 'scim.validation-run-details' -or $report.collection.status -ne 'Completed' -or
        $report.diagnosticScope.name -ne 'FailureFocused' -or -not $report.finalResults.testResults -or
        $report.fullRun.status -notin @('Succeeded', 'Failed', 'Cancelled', 'TimedOut', 'Aborted')) {
        throw 'Offline correction requires a completed FailureFocused report with recorded test results and a terminal root run.'
    }
    $requests = $report.runtime.evidenceRequests.ContentPayload
    if (-not $requests -or $requests.count -lt 1 -or -not $requests.Contains('failed') -or $requests.failed -ne 0) {
        throw 'Offline correction requires recorded content-request metrics proving zero failed downloads.'
    }
    $coreFailures = @($report.tests | Where-Object { $_.applicable -and -not $_.authenticationMethod -and -not $_.passing -and -not $_.nonBlockingWarning })
    $recordedFailure = $coreFailures.Count -gt 0 -or
        [string]$report.finalResults.overallResult -match '^(?i:fail|failed)$' -or
        $report.fullRun.status -ne 'Succeeded' -or
        @($report.authentication.methodResults | Where-Object { -not $_.passing }).Count -gt 0
    if (-not $recordedFailure) { throw 'This narrow offline correction cannot establish gallery readiness; an independently recorded non-ready outcome is required.' }
    $classificationReason = 'Successful data-producing action supplied no readable output evidence.'
    $corrected = [System.Collections.Generic.List[object]]::new()
    $resolvedSources = [System.Collections.Generic.HashSet[string]]::new()
    $base = "https://management.azure.com/subscriptions/$([uri]::EscapeDataString($report.environment.subscriptionId.value))/resourceGroups/$([uri]::EscapeDataString($report.environment.resourceGroupName.value))/providers/Microsoft.Web/sites/$([uri]::EscapeDataString($report.environment.logicAppName.value))/hostruntime/runtime/webhooks/workflow/api/management"
    function Resolve-RecordedComposeEmptyString($Entry, [string] $Uri, [string] $ActionName) {
        $availability = $Entry.contentAvailability
        $p = $Entry.evidence.properties
        $source = "$Uri/outputs"
        $matches = @($report.evidenceFailures | Where-Object { $_.required -and $_.source -eq $source -and $_.reason -eq $classificationReason })
        $protected = @($Entry.securityExclusions | Where-Object source -eq 'outputs').Count -gt 0
        if ($Entry.type -eq 'Compose' -and $Entry.status -eq 'Succeeded' -and $Entry.collectionState -eq 'Completed' -and
            $Entry.payloadCollection -in @('TopLevelDiagnosticPayloads', 'RequiredDiagnosticRepetition') -and
            $availability.outputs.status -eq 'Unavailable' -and $Entry.Contains('outputs') -and $null -eq $Entry.outputs -and
            $availability.inputs.status -in @('Collected', 'ReusedSanitized') -and
            $Entry.inputs -is [string] -and $Entry.inputs.Length -eq 0 -and
            $p.outputsLink.uri -and $p.outputsLink.contentSize -eq 2 -and -not $protected -and $matches.Count -eq 1) {
            $Entry.outputs = ''
            $availability.outputs = @{
                status = 'Collected'; presenceSource = 'OfflineComposeIdentityCorrection'
                reason = 'Legacy empty-string parsing bug corrected from collected Compose input identity, two-byte output metadata, matching classification-only gap and zero failed content downloads. No new HTTP observation is asserted.'
            }
            [void]$resolvedSources.Add($source)
            $corrected.Add(@{ source = $source; action = $ActionName; repetition = $Entry.name; valueKind = 'EmptyString'; outputContentSize = 2 })
        }
        $kind = if ($Entry.repetitionCollection.kind -in @('repetitions', 'scopeRepetitions')) { $Entry.repetitionCollection.kind } else { 'repetitions' }
        foreach ($rep in $Entry.repetitions) {
            Resolve-RecordedComposeEmptyString $rep "$Uri/$kind/$([uri]::EscapeDataString($rep.name))" $ActionName
        }
    }
    foreach ($workflow in $report.workflows) {
        $runUri = "$base/workflows/$([uri]::EscapeDataString($workflow.name))/runs/$([uri]::EscapeDataString($workflow.runId))"
        foreach ($action in $workflow.actions) {
            Resolve-RecordedComposeEmptyString $action "$runUri/actions/$([uri]::EscapeDataString($action.name))" $action.name
        }
    }
    if (-not $corrected.Count) { throw 'No empty-string Compose classification gaps have sufficient recorded proof for offline correction.' }
    $originalExitCode = $report.galleryReadiness.exitCode
    $report.evidenceFailures = @($report.evidenceFailures | Where-Object {
        -not ($_.required -and $_.reason -eq $classificationReason -and $resolvedSources.Contains([string]$_.source))
    })
    $missing = @($report.evidenceFailures | Where-Object required).Count
    $report.completeness.requiredUnavailableCount = $missing
    $report.completeness.complete = $missing -eq 0
    $report.galleryReadiness.ready = $false
    $report.galleryReadiness.status = if ($missing) { 'Incomplete' } else { 'NotReady' }
    $report.galleryReadiness.result = if ($missing) { 'INCOMPLETE' } else { 'NOT_GALLERY_READY' }
    $report.galleryReadiness.exitCode = if ($missing) { 2 } else { 1 }
    $report.galleryReadiness.reason = if ($missing) { 'Required evidence remains unavailable after narrow offline empty-string correction.' } else { 'Evidence is complete within the recorded diagnostic scope; original functional, authentication or runtime failures still prevent gallery readiness.' }
    $report.offlineFinalization = @{
        kind = 'LegacyComposeEmptyStringPresenceCorrection'; correctedOutputCount = $corrected.Count
        sourceReportSha256 = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash.ToLowerInvariant()
        corrector = @{ fileName = [IO.Path]::GetFileName($PSCommandPath); sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
        originalExitCode = $originalExitCode; networkRequests = 0; corrections = @($corrected)
        provenance = 'Original run/source provenance, semantic tests, request metrics and failed functional results are preserved. Source report was read only; this is not a new collection or deployment.'
    }
    return $report
}

function Write-ScimValidationReport {
    param($Report, [string] $WorkDirectory, [switch] $Zip)
    [void][IO.Directory]::CreateDirectory($WorkDirectory)
    $jsonPath = Join-Path $WorkDirectory 'validation-run-details.json'
    $markdownPath = Join-Path $WorkDirectory 'validation-report.md'
    [IO.File]::WriteAllText($jsonPath, (ConvertTo-ScimCanonicalJson $Report) + "`n", [Text.UTF8Encoding]::new($false))
    function Cell($value) { return ([System.Net.WebUtility]::HtmlEncode([string]$value) -replace '\|', '&#124;' -replace '[\r\n]', ' ') }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# SCIM production validation report')
    $lines.Add('')
    $lines.Add("**$($Report.galleryReadiness.status)** — $($Report.galleryReadiness.reason)")
    $lines.Add('')
    $lines.Add("Schema: $($Report.schemaVersion). Orchestrator run: $(if ($Report.orchestratorRunId) { Cell $Report.orchestratorRunId } else { 'Not executed' }).")
    $lines.Add("Agent: $(Cell $Report.provenance.agent.fileName); SHA256: $(Cell $Report.provenance.agent.sha256). Source revision: $(Cell $Report.provenance.sourceGit.revision); dirty: $(Cell $Report.provenance.sourceGit.dirty).")
    $lines.Add("Required unavailable evidence: $($Report.completeness.requiredUnavailableCount). Optional unavailable evidence: $($Report.completeness.optionalUnavailableCount).")
    $lines.Add("Reporting source VERSION: $(Cell $Report.provenance.sourceVersion.value); VERSION SHA256: $(Cell $Report.provenance.sourceVersion.sha256). $(Cell $Report.provenance.sourceVersion.scope)")
    $lines.Add("Historical deployed version: $(Cell $Report.provenance.executedVersion.value). Recorded authentication policy: $(Cell $Report.authentication.recordedPolicy). $(Cell $Report.historicalRun.unavailableReason)")
    $lines.Add("Caller-recorded historical source VERSION: $(Cell $Report.historicalRun.metadata.sourceVersion.value); original VERSION SHA256: $(Cell $Report.historicalRun.metadata.sourceVersion.sha256). Historical policy claim: $(Cell $Report.historicalRun.metadata.authenticationPolicy).")
    $lines.Add("Deployed version matches reporting source: $(Cell $Report.provenance.comparison.deployedVersionMatchesSource). $(Cell $Report.provenance.comparison.reason)")
    $lines.Add("Intentional security exclusions: $($Report.completeness.securityExcludedCount). $(Cell $Report.completeness.scope)")
    $lines.Add("Diagnostic scope: $(Cell $Report.diagnosticScope.name). $(Cell $Report.diagnosticScope.metadata) $(Cell $Report.diagnosticScope.payloads) $(Cell $Report.diagnosticScope.successfulRepeatedPollPayloads)")
    if ($Report.offlineFinalization) { $lines.Add("Offline finalization: $(Cell $Report.offlineFinalization.kind); corrected outputs: $($Report.offlineFinalization.correctedOutputCount); source report SHA256: $(Cell $Report.offlineFinalization.sourceReportSha256). $(Cell $Report.offlineFinalization.provenance)") }
    if ($Report.resume.requested) { $lines.Add("Resumed sanitized terminal payloads: $($Report.resume.reusedPayloadCount). $(Cell $Report.resume.policy)") }
    $lines.Add("Full run: $(Cell $Report.fullRun.timing.startUtc) → $(Cell $Report.fullRun.timing.endUtc); duration: $(Cell $Report.fullRun.timing.durationMilliseconds) ms.")
    $lines.Add('')
    $lines.Add('## Agent and setup timing')
    $lines.Add("Agent setup-to-cleanup window: $(Cell $Report.agentRun.timing.startUtc) → $(Cell $Report.agentRun.timing.endUtc); duration: $(Cell $Report.agentRun.timing.durationMilliseconds) ms; status: $(Cell $Report.agentRun.status); timing: $(Cell $Report.agentRun.timingState).")
    $lines.Add("$(Cell $Report.agentRun.timing.unavailableReason) $(Cell $Report.agentRun.statusUnavailableReason)")
    $lines.Add("Recorded events: $(Cell $Report.agentEvents.status). $(Cell $Report.agentEvents.unavailableReason)")
    $lines.Add('| Event | Kind | Parent | Status | UTC start | UTC end | Duration (ms) | Timing availability | Details |')
    $lines.Add('|---|---|---|---|---|---|---|---|---|')
    foreach ($event in $Report.agentEvents.events) {
        $detailText = if ($event.details -is [string]) { $event.details } elseif ($null -ne $event.details) { ConvertTo-ScimCanonicalJson $event.details } else { '' }
        $lines.Add("| $(Cell $event.name) | $(Cell $event.kind) | $(Cell $event.parentName) | $(Cell $event.status) | $(Cell $event.timing.startUtc) | $(Cell $event.timing.endUtc) | $(Cell $event.timing.durationMilliseconds) | $(Cell $event.timingState): $(Cell $event.unavailableReason) | $(Cell $detailText) |")
    }
    $lines.Add('')
    $lines.Add('Runtime success is not test success. The JSON contains sanitized action, scope, trigger, repetition, provenance, environment and timing details.')
    $lines.Add('')
    $lines.Add('## Workflow execution')
    $lines.Add('| Workflow | Exact run ID | Status | UTC start | UTC end | Duration (ms) |')
    $lines.Add('|---|---|---|---|---|---|')
    foreach ($wf in $Report.workflows) { $lines.Add("| $(Cell $wf.name) | $(Cell $wf.runId) | $(Cell $wf.status) | $(Cell $wf.timing.startUtc) | $(Cell $wf.timing.endUtc) | $(Cell $wf.timing.durationMilliseconds) |") }
    $lines.Add('')
    $lines.Add('## Selected authentication methods')
    $lines.Add((Cell ($Report.authentication.selectedMethods -join ', ')))
    $lines.Add((Cell $Report.authentication.policy))
    $lines.Add("Selection source: $(Cell $Report.authentication.selectionSource). Recorded executed selection: $(Cell ($Report.authentication.recordedSelectedMethods -join ', ')). Selection mismatch: $(Cell $Report.authentication.selectionMismatch).")
    $lines.Add("Recorded authentication aggregate: $(Cell $Report.authentication.recordedAggregateResult). Aggregate contradicts selected-method policy: $(Cell $Report.authentication.aggregatePolicyMismatch).")
    foreach ($method in $Report.authentication.methodResults) { $lines.Add("- $(Cell $method.method): passing=$($method.passing); eligible=$($method.eligible). $(Cell $method.reason)") }
    $lines.Add("Direct SCIM request transport: $(Cell $Report.authentication.scimRequestTransport.value). $(Cell $Report.authentication.scimRequestTransport.unavailableReason)")
    $lines.Add('')
    $lines.Add('## Semantic test results')
    $lines.Add("Passed: $($Report.testSummary.passed); optional warnings: $($Report.testSummary.warnings); failed: $($Report.testSummary.failed); not applicable: $($Report.testSummary.notApplicable); unknown: $($Report.testSummary.unknown).")
    $lines.Add('| Test | Result | Applicable | Reason |')
    $lines.Add('|---|---|---|---|')
    foreach ($test in $Report.tests) { $lines.Add("| $(Cell $test.name) | $(Cell $test.semanticResult) | $(Cell $test.applicable) | $(Cell $test.applicabilityReason) |") }
    $lines.Add('')
    $lines.Add('## Unavailable evidence and next actions')
    foreach ($failure in $Report.evidenceFailures) { $lines.Add("- $(Cell $failure.source): $(Cell $failure.reason) Required: $($failure.required). Supply the missing evidence or resolve read permissions and export again.") }
    foreach ($exclusion in $Report.securityExclusions) { $lines.Add("- Security exclusion: $(Cell $exclusion.source). $(Cell $exclusion.reason)") }
    [IO.File]::WriteAllText($markdownPath, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    if ($Zip) { Compress-Archive -LiteralPath @($jsonPath, $markdownPath) -DestinationPath (Join-Path $WorkDirectory 'validation-report.zip') -Force }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        if (-not $WorkDirectory -or -not $AgentPath) { throw 'WorkDirectory and AgentPath are required.' }
        $WorkDirectory = [IO.Path]::GetFullPath($WorkDirectory)
        $checkpointPath = Join-Path $WorkDirectory 'validation-run-details.checkpoint.json'
        $previousReport = $null
        if (-not $ResumeReportPath -and (Test-Path -LiteralPath $checkpointPath)) {
            $candidate = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json -AsHashtable
            if ($candidate.orchestratorRunId -eq $OrchestratorRunId -and $candidate.environment.subscriptionId.value -eq $SubscriptionId -and
                $candidate.environment.resourceGroupName.value -eq $ResourceGroupName -and $candidate.environment.logicAppName.value -eq $LogicAppName) { $ResumeReportPath = $checkpointPath }
        }
        if ($ResumeReportPath) {
            if (-not [IO.Path]::IsPathRooted($ResumeReportPath)) { $ResumeReportPath = Join-Path $WorkDirectory $ResumeReportPath }
            $previousReport = Get-Content -LiteralPath $ResumeReportPath -Raw | ConvertFrom-Json -AsHashtable
        }
        if ($MetadataPath -and [IO.Path]::GetFileName($MetadataPath) -match '(?i)(parameters|appsettings).*\.json$') { throw 'Configuration files are not accepted as report metadata.' }
        $metadata = if ($MetadataPath) { Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
        if (-not $metadata.environment) { $metadata.environment = @{} }
        if (-not $metadata.harness) { $metadata.harness = @{} }
        if ($TenantId) { $metadata.environment.tenantId = $TenantId }
        if ($metadata.provisioningLogPath -and -not [IO.Path]::IsPathRooted($metadata.provisioningLogPath)) { $metadata.provisioningLogPath = Join-Path $WorkDirectory $metadata.provisioningLogPath }
        if (-not $WorkflowDirectory) {
            $WorkflowDirectory = if (Test-Path -LiteralPath (Join-Path $WorkDirectory 'Orchestrator_Workflow.json')) { $WorkDirectory } else { $PSScriptRoot }
        }
        $runtime = @{ powerShell = $PSVersionTable.PSVersion.ToString(); os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription; azureCli = $null; azureCliUnavailableReason = $null }
        $token = $null
        $authenticationState = $null
        $authFailure = $null
        if ($OrchestratorRunId) {
            try {
                if (-not $SubscriptionId -or -not $ResourceGroupName -or -not $LogicAppName) { throw 'SubscriptionId, ResourceGroupName and LogicAppName are required for executed runs.' }
                $tokenObject = Get-ScimArmAuthentication -SubscriptionId $SubscriptionId -TenantId $TenantId
                $runtime.armAuthenticationSelector = $tokenObject.selector
                $token = $tokenObject.accessToken
                if (-not $token) { throw 'Azure CLI returned no ARM access token.' }
                $KnownSecrets += $token
                $authenticationState = New-ScimArmRequestState -Authentication $tokenObject -SubscriptionId $SubscriptionId -TenantId $TenantId
                if (-not $TenantId) { $metadata.environment.tenantId = $tokenObject.tenant }
                $account = & az account show --subscription $SubscriptionId --query '{tenantId:tenantId,operatorIdentity:user}' --output json --only-show-errors 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $accountObject = $account | ConvertFrom-Json -AsHashtable
                    if (-not $TenantId -or $accountObject.tenantId -eq $TenantId) { $metadata.environment.operatorIdentity = $accountObject.operatorIdentity }
                }
                $version = & az version --query '"azure-cli"' --output tsv 2>$null
                if ($LASTEXITCODE -eq 0) { $runtime.azureCli = [string]$version } else { $runtime.azureCliUnavailableReason = 'Azure CLI version could not be read.' }
            } catch { $authFailure = $_.Exception.Message; $runtime.azureCliUnavailableReason = 'Azure CLI authentication or environment discovery failed.' }
        } else { $runtime.azureCliUnavailableReason = 'No execution requested; Azure CLI was not invoked.' }
        $refreshingRequest = ${function:Invoke-ScimRefreshingRequest}
        $request = {
            param($uri, $arm, $receipt)
            if ($authFailure) { throw $authFailure }
            return ,(& $refreshingRequest $authenticationState $uri $arm $receipt)
        }.GetNewClosure()
        $report = New-ScimValidationReport -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -LogicAppName $LogicAppName `
            -OrchestratorRunId $OrchestratorRunId -AgentPath $AgentPath -WorkflowDirectory $WorkflowDirectory -Metadata $metadata `
            -KnownSecrets $KnownSecrets -Request $request -RuntimeMetadata $runtime -WorkDirectory $WorkDirectory -AuthenticationState $authenticationState -PreviousReport $previousReport -CheckpointPath $checkpointPath
        Write-ScimValidationReport $report $WorkDirectory -Zip:$Zip
        if (Test-Path -LiteralPath $checkpointPath) { Remove-Item -LiteralPath $checkpointPath -Force }
        $token = $null; $tokenResponse = $null; $tokenObject = $null; $KnownSecrets = @()
        if ($authenticationState) { $authenticationState.authentication = $null; $authenticationState.secretLiterals.Clear() }
        Write-Host "Sanitized report written. Readiness: $($report.galleryReadiness.status). Required evidence unavailable: $($report.completeness.requiredUnavailableCount)."
        exit $report.galleryReadiness.exitCode
    } catch {
        # Never echo raw exception bodies, CLI output, metadata, headers or credentials.
        Write-Error 'Report export failed before completion. Saved sanitized actions remain in validation-run-details.checkpoint.json when available; rerun with the same root and site to resume. No gallery readiness is claimed; existing canonical reports were not refreshed.' -ErrorAction Continue
        exit 2
    }
}
