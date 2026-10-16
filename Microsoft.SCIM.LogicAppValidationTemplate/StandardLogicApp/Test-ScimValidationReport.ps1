#requires -Version 7.0
<#
.SYNOPSIS
Runs dependency-free, offline reporting regression tests. No Azure CLI or network.
.EXAMPLE
pwsh -NoProfile -File .\Test-ScimValidationReport.ps1
.EXAMPLE
pwsh -NoProfile -File .\Test-ScimValidationReport.ps1 -EvidenceDirectory .\report-contract-evidence
#>
[CmdletBinding()]
param([string] $EvidenceDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Export-ScimValidationReport.ps1')
$script:checks = 0
function Assert-Report($Condition, [string] $Message) {
    $script:checks++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$fixtureDirectory = Join-Path $PSScriptRoot ('.scim-report-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureDirectory)
try {
    $secret = 'fixture-opaque-secret+/=42'
    $jwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.signature'
    $fixtures = @(
        @{ headers = @{ Authorization = 'Bearer raw-auth-token'; 'Proxy-Authorization' = 'Basic raw-proxy-token'; Cookie = 'session=raw-cookie'; 'Set-Cookie' = 'session=raw-set-cookie'; 'X-Api-Key' = 'raw-api-key'; 'Content-Type' = 'application/json'; 'x-ms-request-id' = 'safe-correlation'; 'Custom-Credential' = 'raw-custom-header' } },
        @{ embedded = '{"inner":"{\"client_secret\":\"raw-embedded-secret\"}"}' },
        @{ body = 'client_secret=raw-form-secret&client_assertion=raw-form-assertion&access_token=raw-form-access&refresh_token=raw-form-refresh&id_token=raw-form-id&password=raw-form-password' },
        @{ body = 'client_secret%3Draw-encoded-secret%26grant_type%3Dclient_credentials' },
        @{ error = 'Failure access_token: raw-error-token; client_secret="raw-error-secret" password=raw-error-password' },
        @{ uri = 'https://sample.blob.core.windows.net/container/data?sv=2026&sig=raw-sas-signature&custom=raw-query-secret#raw-fragment-secret' },
        @{ nested = @(@{ token = 'raw-nested-token'; connectionString = 'raw-connection-string'; result = 'PASSED' }); jwt = $jwt; literal = $secret },
        @{ body = '{"access_token":"raw-payload-token","opaque":"raw-token-response-extra"}' },
        @{ headersText = "Authorization: Bearer raw-text-auth`nCookie: session=raw-text-cookie`nSet-Cookie: raw-text-setcookie" },
        @{ value = 'DefaultEndpointsProtocol=https;AccountName=sample;AccountKey=raw-account-key;EndpointSuffix=core.windows.net' },
        @{ value = ('prefix ' + [uri]::EscapeDataString($secret) + ' suffix') },
        @{ value = 'https://sample.azure.com/path?api_key=raw-url-key&password=raw-url-password' },
        @{ value = '{"error":"{\"refresh_token\":\"raw-double-json-token\"}"}' },
        @{ error = 'Request failed with {\"access_token\":\"raw-escaped-error-token\"}' },
        @{ error = 'access token is raw-spaced-token; client secret: raw-spaced-secret' },
        @{ error = 'client_secret&#61;raw-html-secret' },
        @{ error = 'client\u005fsecret=raw-unicode-secret' }
    )
    $safe = Protect-ScimValue $fixtures @($secret)
    $safeJson = ConvertTo-ScimCanonicalJson $safe
    foreach ($forbidden in @(
        'raw-auth-token', 'raw-proxy-token', 'raw-cookie', 'raw-set-cookie', 'raw-api-key', 'raw-custom-header',
        'raw-embedded-secret', 'raw-form-secret', 'raw-form-assertion', 'raw-form-access', 'raw-form-refresh',
        'raw-form-id', 'raw-form-password', 'raw-encoded-secret', 'raw-error-token', 'raw-error-secret', 'raw-error-password',
        'raw-sas-signature', 'raw-query-secret', 'raw-fragment-secret', 'raw-nested-token', 'raw-connection-string',
        'raw-payload-token', 'raw-token-response-extra', 'raw-text-auth', 'raw-text-cookie', 'raw-text-setcookie',
        'raw-account-key', 'raw-url-key', 'raw-url-password', 'raw-double-json-token',
        'raw-escaped-error-token', 'raw-spaced-token', 'raw-spaced-secret', 'raw-html-secret', 'raw-unicode-secret', $secret, $jwt
    )) { Assert-Report (-not $safeJson.Contains($forbidden)) "Secret redacted: $forbidden" }
    Assert-Report ($safeJson.Contains('safe-correlation')) 'Safe correlation header retained'
    Assert-Report ($safeJson.Contains('application/json')) 'Allowlisted content-type retained'
    Assert-Report ($safeJson.Contains('PASSED')) 'Semantic result retained'
    Assert-Report ((ConvertTo-ScimCanonicalJson (Protect-ScimValue $safe @($secret))) -eq $safeJson) 'Repeated sanitization preserves already-redacted fixture content'
    $prose = 'Acquire an ARM token for the selected tenant.'
    Assert-Report ((Protect-ScimText $prose) -eq $prose) 'Harmless token-for prose is not treated as a credential assignment'
    $maskedUrl = 'https://sample.azure.com/path?[REDACTED QUERY]'
    Assert-Report ((Protect-ScimText (Protect-ScimText $maskedUrl)) -eq $maskedUrl) 'Query redaction marker is idempotent and does not accumulate suffixes'
    Assert-Report ((Protect-ScimText 'access_token: [REDACTED]') -eq 'access_token: [REDACTED]') 'Credential-assignment redaction marker is idempotent'
    foreach ($diagnosticText in @(
        'StatusCode: 400', 'statusCode=400', '"statusCode":400', 'STATUSCODE is 400',
        '"errorCode":400', 'errorCode: SystemForCrossDomainIdentityManagementServiceIncompatible',
        'status-code=400; error_code=invalidSyntax',
        'StatusCode: 400; response: {"errorCode":400,"scimType":"invalidSyntax","detail":"Invalid filter."}'
    )) {
        Assert-Report ((Protect-ScimText $diagnosticText) -eq $diagnosticText) "Diagnostic code label is not an OAuth code assignment: $diagnosticText"
    }
    foreach ($codeAssignment in @(
        'code=fixture-oauth-code', 'code: fixture-oauth-code', 'code is fixture-oauth-code',
        '"code":"fixture-oauth-code"', "'code'='fixture-oauth-code'",
        'authorization_code=fixture-oauth-code', '"authorization_code":"fixture-oauth-code"',
        'authorization-code: fixture-oauth-code', 'authorization code is fixture-oauth-code',
        'CODE=fixture-oauth-code'
    )) {
        $redactedCode = Protect-ScimText $codeAssignment
        Assert-Report ($redactedCode.Contains('[REDACTED]') -and -not $redactedCode.Contains('fixture-oauth-code')) "Exact OAuth code assignment remains redacted: $codeAssignment"
        Assert-Report ((Protect-ScimText $redactedCode) -eq $redactedCode) "OAuth code redaction stays idempotent: $codeAssignment"
    }
    $diagnosticReason = 'StatusCode: 400; response: {"errorCode":400,"scimType":"invalidSyntax"}; code=fixture-oauth-code; authorization_code=fixture-other-code'
    $diagnosticLogs = Protect-ScimValue @{ provisioningLogs = @{
        errorCode = 'SystemForCrossDomainIdentityManagementServiceIncompatible'; reason = $diagnosticReason
    } }
    Assert-Report ($diagnosticLogs.provisioningLogs.reason.Contains('StatusCode: 400') -and
        $diagnosticLogs.provisioningLogs.reason.Contains('"errorCode":400') -and
        $diagnosticLogs.provisioningLogs.reason.Contains('"scimType":"invalidSyntax"') -and
        $diagnosticLogs.provisioningLogs.errorCode -eq 'SystemForCrossDomainIdentityManagementServiceIncompatible') 'Nested provisioning diagnostics retain HTTP400, invalidSyntax and structured errorCode'
    Assert-Report (-not $diagnosticLogs.provisioningLogs.reason.Contains('fixture-oauth-code') -and
        -not $diagnosticLogs.provisioningLogs.reason.Contains('fixture-other-code')) 'OAuth code assignments are still redacted beside retained provisioning diagnostics'
    Assert-Report ((Protect-ScimValue @{ message = 'ordinary failure'; result = 'FAILED' }).message -eq 'ordinary failure') 'Ordinary error retained'
    Assert-Report ((ConvertTo-ScimCanonicalJson @{ z = 2; a = @{ b = 3; a = 1 } }) -eq (ConvertTo-ScimCanonicalJson @{ a = @{ a = 1; b = 3 }; z = 2 })) 'Canonical key ordering'
    $authCalls = [System.Collections.Generic.List[object]]::new()
    $fakeCli = {
        param($commandArguments)
        $authCalls.Add(@($commandArguments))
        if ('--tenant' -in $commandArguments -and '--subscription' -in $commandArguments) {
            return @{ exitCode = 1; output = 'Please specify only one of subscription and tenant, not both' }
        }
        return @{ exitCode = 0; output = '{"accessToken":"fixture-arm-token","tenant":"fixture-tenant"}' }
    }.GetNewClosure()
    $tenantAuth = Get-ScimArmAuthentication -SubscriptionId 'fixture-subscription' -TenantId 'fixture-tenant' -InvokeCli $fakeCli
    Assert-Report ($tenantAuth.selector -eq 'tenant' -and $tenantAuth.accessToken -eq 'fixture-arm-token') 'Explicit tenant authentication succeeds with CLI seam'
    Assert-Report ('--tenant' -in $authCalls[0] -and '--subscription' -notin $authCalls[0]) 'Explicit tenant token request never combines mutually exclusive CLI selectors'
    Assert-Report ('https://management.azure.com/' -in $authCalls[0]) 'Authentication targets the ARM resource'
    $subscriptionAuth = Get-ScimArmAuthentication -SubscriptionId 'fixture-subscription' -InvokeCli $fakeCli
    Assert-Report ($subscriptionAuth.selector -eq 'subscription' -and '--subscription' -in $authCalls[1] -and '--tenant' -notin $authCalls[1]) 'Subscription-only token acquisition remains supported'
    $invalidAuthReason = $null
    try { [void](Get-ScimArmAuthentication -TenantId 'fixture-tenant' -InvokeCli { @{ exitCode = 0; output = 'raw-invalid-auth-payload' } }) }
    catch { $invalidAuthReason = $_.Exception.Message }
    Assert-Report ($invalidAuthReason -and -not $invalidAuthReason.Contains('raw-invalid-auth-payload')) 'Malformed CLI output is not echoed into authentication diagnostics'
    $wrongTenantReason = $null
    try { [void](Get-ScimArmAuthentication -TenantId 'different-tenant' -InvokeCli $fakeCli) }
    catch { $wrongTenantReason = $_.Exception.Message }
    Assert-Report ($wrongTenantReason -match 'different tenant') 'Authentication cannot silently use a different tenant'
    $failedAuthReason = $null
    try { [void](Get-ScimArmAuthentication -TenantId 'fixture-tenant' -InvokeCli { @{ exitCode = 1; output = 'accessToken=raw-failed-auth-output' } }) }
    catch { $failedAuthReason = $_.Exception.Message }
    Assert-Report ($failedAuthReason -match 'CLI exit 1' -and -not $failedAuthReason.Contains('raw-failed-auth-output')) 'Failed authentication records a safe exit diagnostic, not raw output'
    $expiryAuth = Get-ScimArmAuthentication -TenantId 'fixture-tenant' -InvokeCli { @{ exitCode = 0; output = '{"accessToken":"fixture-expiring-token","tenant":"fixture-tenant","expires_on":1767229200}' } }
    Assert-Report ($expiryAuth.expiresUtc.ToUnixTimeSeconds() -eq 1767229200) 'CLI expires_on is retained as an absolute UTC expiry'
    $transportFixture = @{ now = [datetimeoffset]'2026-01-01T00:00:00Z'; acquireCount = 0; sendCount = 0; fail401 = 0; status = 200; linkHadAuthorization = $false }
    $clock = { $transportFixture.now }.GetNewClosure()
    $acquire = {
        param($subscription, $tenant)
        $transportFixture.acquireCount++
        @{ accessToken = "refreshed-fixture-$($transportFixture.acquireCount)"; tenant = $tenant; expiresUtc = $transportFixture.now.AddHours(1) }
    }.GetNewClosure()
    $send = {
        param($uri, $headers)
        $transportFixture.sendCount++
        if ($uri -match 'fixture.azure.com') { $transportFixture.linkHadAuthorization = $headers.ContainsKey('Authorization') }
        $status = if ($transportFixture.fail401 -gt 0) { $transportFixture.fail401--; 401 } else { $transportFixture.status }
        if ($status -ne 200) {
            $errorObject = [System.Net.Http.HttpRequestException]::new("Fixture final HTTP$status")
            $errorObject.Data['StatusCode'] = $status
            throw $errorObject
        }
        return @{ value = @() }
    }.GetNewClosure()
    $transport = New-ScimArmRequestState @{ accessToken = 'initial-fixture'; expiresUtc = $transportFixture.now.AddMinutes(4) } 'fixture-subscription' 'fixture-tenant' $acquire $send $clock
    [void](Invoke-ScimRefreshingRequest $transport 'https://management.azure.com/expiry' $true)
    Assert-Report ($transport.refreshCount -eq 1 -and $transportFixture.sendCount -eq 1) 'Five-minute expiry margin refreshes before sending the ARM request'
    $transportFixture.fail401 = 1
    $before = $transportFixture.sendCount
    [void](Invoke-ScimRefreshingRequest $transport 'https://management.azure.com/401' $true)
    Assert-Report ($transport.retry401Count -eq 1 -and $transportFixture.sendCount -eq $before + 2) 'First ARM 401 refreshes credentials and retries exactly once'
    Assert-Report ((Protect-ScimText 'refreshed-fixture-2' $transport.secretLiterals) -eq '[REDACTED]') 'Refreshed token literals remain available for defense-in-depth redaction'
    $transportFixture.fail401 = 2
    $before = $transportFixture.sendCount
    $final401 = $null
    try { [void](Invoke-ScimRefreshingRequest $transport 'https://management.azure.com/still401' $true) } catch { $final401 = $_.Exception.Message }
    Assert-Report ($transportFixture.sendCount -eq $before + 2 -and $final401 -match 'HTTP401') 'Repeated 401 preserves the final error after only one retry'
    $transportFixture.status = 403
    $before = $transportFixture.sendCount
    try { [void](Invoke-ScimRefreshingRequest $transport 'https://management.azure.com/403' $true) } catch { }
    Assert-Report ($transportFixture.sendCount -eq $before + 1) 'Non-401 HTTP errors are not retried or hidden'
    $transportFixture.status = 200
    [void](Invoke-ScimRefreshingRequest $transport 'https://fixture.azure.com/content' $false)
    Assert-Report (-not $transportFixture.linkHadAuthorization) 'Signed content requests never receive ARM Authorization'
    $sameCachedAuth = @{ accessToken = 'same-cached-token'; expiresUtc = $transportFixture.now.AddMinutes(3) }
    $sameCached = New-ScimArmRequestState $sameCachedAuth 'fixture-subscription' 'fixture-tenant' { $sameCachedAuth }.GetNewClosure() $send $clock
    [void](Invoke-ScimRefreshingRequest $sameCached 'https://management.azure.com/one' $true)
    [void](Invoke-ScimRefreshingRequest $sameCached 'https://management.azure.com/two' $true)
    Assert-Report ($sameCached.refreshCount -eq 1) 'Same near-expiry CLI cache token does not cause per-request refresh storms'
    Assert-Report ($sameCached.secretLiterals.Count -eq 1) 'Repeated cached credentials do not duplicate secret-redaction literals'
    $transportFixture.fail401 = 2
    $refreshingRequest = ${function:Invoke-ScimRefreshingRequest}
    $finalErrorContext = @{
        failures = [System.Collections.Generic.List[object]]::new(); secrets = $transport.secretLiterals
        request = { param($uri, $arm) & $refreshingRequest $transport $uri $arm }.GetNewClosure()
    }
    [void](Invoke-ScimEvidenceRequest $finalErrorContext 'https://management.azure.com/final401')
    Assert-Report ($finalErrorContext.failures.Count -eq 1 -and $finalErrorContext.failures[0].httpStatus -eq 401) 'Exhausted 401 recovery records one final failure with its real HTTP status'
    Assert-Report ($finalErrorContext.failures[0].reason -match 'HTTP401') 'Nested-host closure calls the captured refreshing transport rather than failing private function lookup'
    $contractTests = @(@{ testName = 'Validate_Credentials_Test'; testCategory = 'Mandatory/StrictOneSuccess'; testResult = 'success' })
    for ($i = 1; $i -le 17; $i++) { $contractTests += @{ testName = "Core_$i"; testCategory = 'Mandatory/StrictSuccess'; testResult = 'success' } }
    $contractTests += @{ testName = 'Restore_User_Test'; testCategory = 'Mandatory/StrictSuccess'; testResult = 'success (SoftDeleteRestore)' }
    foreach ($name in @('Delete_Group_Test', 'Restore_Group_Test')) { $contractTests += @{ testName = $name; testCategory = 'Skippable/OptionalSuccess'; testResult = 'WARNING - optional provisioning evidence unavailable' } }
    foreach ($name in @('Group_Update_Add_Member_Test', 'Group_Update_Remove_Member_Test', 'User_Update_Manager_Test')) { $contractTests += @{ testName = $name; testCategory = 'Skippable/StrictSuccess'; testResult = 'FAILED - fixture validation failure' } }
    $contractTests += @{ testName = 'Federated_Identity_Test'; testCategory = 'Mandatory/StrictOneSuccess'; testResult = 'NOT_APPLICABLE - authentication method not declared for this validation' }
    $classifiedContract = @(Get-ScimSemanticTests @{ testResults = $contractTests } @{} @() @('OAuth2ClientCredentials'))
    Assert-Report ($classifiedContract.Count -eq 25 -and @($classifiedContract | Where-Object classification -eq 'Passed').Count -eq 19) 'Actual 25-test contract accepts ordinary and annotated success'
    Assert-Report (@($classifiedContract | Where-Object classification -eq 'Warning').Count -eq 2 -and @($classifiedContract | Where-Object classification -eq 'Failed').Count -eq 3) 'OptionalSuccess warnings stay visible without becoming failed tests'
    Assert-Report (@($classifiedContract | Where-Object classification -eq 'NotApplicable').Count -eq 1) 'Undeclared federation alternative is explicitly not applicable'
    Assert-Report (@($classifiedContract | Where-Object { $_.authenticationMethod -eq 'OAuth2ClientCredentials' -and $_.passing }).Count -eq 1) 'Validate_Credentials_Test is recognized as the OAuth gallery alternative'
    $blockingContract = @($classifiedContract | Where-Object { $_.applicable -and -not $_.passing -and -not $_.nonBlockingWarning -and -not $_.authenticationMethod })
    Assert-Report (($blockingContract.name -join ',') -eq 'Group_Update_Add_Member_Test,Group_Update_Remove_Member_Test,User_Update_Manager_Test') 'Only the three genuine core failures block the actual contract'

    $timing = Get-ScimTiming @{ startTime = '2026-01-01T01:00:00+01:00'; endTime = '2026-01-01T00:00:02Z' }
    Assert-Report ($timing.durationMilliseconds -eq 2000) 'UTC elapsed time'
    Assert-Report ($timing.startUtc -eq '2026-01-01T00:00:00.0000000Z') 'UTC start conversion'
    Assert-Report ($null -eq (Get-ScimTiming @{}).durationMilliseconds) 'Missing timing is not invented'
    Assert-Report ($null -ne (Get-ScimTiming @{ startTime = 'bad'; endTime = 'bad' }).unavailableReason) 'Invalid timing has reason'

    $paginationCalls = [System.Collections.Generic.List[string]]::new()
    $ctx = @{ failures = [System.Collections.Generic.List[object]]::new(); secrets = @(); request = {
        param($uri, $arm)
        $paginationCalls.Add($uri)
        if ($uri -match 'second') { return @{ value = @(@{ name = 'two' }) } }
        return @{ value = @(@{ name = 'one' }); nextLink = 'https://management.azure.com/second' }
    }.GetNewClosure() }
    $pages = Get-ScimEvidencePages $ctx 'https://management.azure.com/first'
    Assert-Report ($pages.Count -eq 2 -and $paginationCalls.Count -eq 2) 'Pagination collects every page'
    foreach ($count in @(0, 1, 2)) {
        $rawItems = @()
        for ($i = 0; $i -lt $count; $i++) { $rawItems += [pscustomobject]@{ name = "raw-item-$i" } }
        $rawContext = @{
            failures = [System.Collections.Generic.List[object]]::new(); secrets = @()
            request = { param($uri, $arm) return ,$rawItems }.GetNewClosure()
        }
        $rawCollection = Get-ScimEvidencePages $rawContext 'https://management.azure.com/workflows'
        Assert-Report ($rawCollection.Count -eq $count -and $rawContext.failures.Count -eq 0) "Raw collection arrays preserve $count items without an envelope"
    }
    $ctx.request = { param($uri, $arm) @{ value = @(); nextLink = 'https://evil.example/steal' } }
    [void](Get-ScimEvidencePages $ctx 'https://management.azure.com/first')
    Assert-Report ($ctx.failures.Count -eq 1) 'Pagination host escape recorded'
    $ctx.failures.Clear()
    $ctx.request = { param($uri, $arm) @{ value = @(); nextLink = $uri } }
    [void](Get-ScimEvidencePages $ctx 'https://management.azure.com/first')
    Assert-Report ($ctx.failures.Count -eq 1) 'Pagination cycle recorded'
    $ctx.failures.Clear()
    $ctx.request = { throw 'Denied access_token=raw-denied-token' }
    [void](Get-ScimEvidencePages $ctx 'https://management.azure.com/denied?sig=raw-denied-sig')
    Assert-Report (-not (ConvertTo-ScimCanonicalJson @($ctx.failures)).Contains('raw-denied')) 'Denied evidence reason and source sanitized'
    $ctx.failures.Clear()
    $unprotected = Get-ScimActionEvidence $ctx @{ name = 'Http'; properties = @{
        status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
    } } 'https://management.azure.com/action' $false @() 'Http'
    Assert-Report ($ctx.failures.Count -eq 1 -and $unprotected.contentAvailability.outputs.status -eq 'Unavailable') 'Missing HTTP output is not silently complete'
    $valueCases = @(
        @{ name = 'Null'; value = $null }, @{ name = 'EmptyString'; value = '' },
        @{ name = 'False'; value = $false }, @{ name = 'Zero'; value = 0 },
        @{ name = 'EmptyArray'; value = @() }, @{ name = 'EmptyObject'; value = @{} },
        @{ name = 'NullString'; value = 'null' }, @{ name = 'FalseString'; value = 'false' },
        @{ name = 'ZeroString'; value = '0' }, @{ name = 'WhitespaceString'; value = ' ' }
    )
    foreach ($valueCase in $valueCases) {
        $valueContext = @{ secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); cachedActions = @{}
            request = { throw 'Inline value unexpectedly requested network access.' } }
        $valueAction = @{ name = 'Compose_Value'; properties = @{
            status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
            inputs = $valueCase.value; outputs = $valueCase.value
        } }
        $valueEvidence = Get-ScimActionEvidence $valueContext $valueAction 'https://management.azure.com/value' $false @() 'Compose'
        Assert-Report ($valueContext.failures.Count -eq 0 -and $valueEvidence.contentAvailability.outputs.status -eq 'Collected' -and $valueEvidence.contentAvailability.inputs.status -eq 'Collected') "Explicit inline $($valueCase.name) is present evidence, not an absent payload"
        Assert-Report ((ConvertTo-ScimCanonicalJson @{ value = $valueEvidence.outputs }) -eq (ConvertTo-ScimCanonicalJson @{ value = $valueCase.value })) "Inline $($valueCase.name) retains its exact JSON value"
        $valueContext.request = {
            param($uri, $arm, $receipt)
            $receipt.httpStatus = 200
            return ,$valueCase.value
        }.GetNewClosure()
        $valueAction.properties.Remove('outputs')
        $valueAction.properties.outputsLink = @{ uri = 'https://fixture.azure.com/value' }
        $downloadedValue = Get-ScimActionEvidence $valueContext $valueAction 'https://management.azure.com/value' $false @() 'Compose'
        Assert-Report ($valueContext.failures.Count -eq 0 -and $downloadedValue.contentAvailability.outputs.status -eq 'Collected' -and $downloadedValue.contentAvailability.outputs.httpStatus -eq 200) "Successful HTTP200 $($valueCase.name) download is proven present independently of its value"
        Assert-Report ((ConvertTo-ScimCanonicalJson @{ value = $downloadedValue.outputs }) -eq (ConvertTo-ScimCanonicalJson @{ value = $valueCase.value })) "Downloaded $($valueCase.name) retains its exact JSON value"
    }
    $absentContext = @{ secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); cachedActions = @{}
        request = { return $null } }
    $absentAction = @{ name = 'Compose_Value'; properties = @{
        status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
    } }
    $absentEvidence = Get-ScimActionEvidence $absentContext $absentAction 'https://management.azure.com/absent' $false @() 'Compose'
    Assert-Report ($absentContext.failures.Count -eq 1 -and $absentEvidence.contentAvailability.outputs.status -eq 'Unavailable') 'A successful Compose with no output property or content link is still a required evidence gap'
    $absentAction.properties.outputsLink = @{ uri = 'https://fixture.azure.com/unproven-null' }
    $unprovenNull = Get-ScimActionEvidence $absentContext $absentAction 'https://management.azure.com/absent' $false @() 'Compose'
    Assert-Report ($unprovenNull.contentAvailability.outputs.status -eq 'Unavailable' -and $absentContext.failures.Count -gt 1) 'An unproven null content response is not silently promoted to a valid JSON null'
    $absentContext.request = { param($uri, $arm, $receipt) $receipt.httpStatus = 200; return $null }
    $nullArmMetadata = Invoke-ScimEvidenceRequest $absentContext 'https://management.azure.com/null-metadata'
    Assert-Report ($null -eq $nullArmMetadata -and $absentContext.failures[-1].reason -match 'without successful HTTP content-response proof') 'Successful HTTP status does not make null ARM metadata a valid workflow or action description'
    $absentContext.request = { throw 'Fixture content download failed.' }
    $failedDownload = Get-ScimActionEvidence $absentContext $absentAction 'https://management.azure.com/failed-download' $false @() 'Compose'
    Assert-Report ($failedDownload.contentAvailability.outputs.status -eq 'Unavailable' -and @($absentContext.failures | Where-Object reason -eq 'Fixture content download failed.').Count -eq 1) 'An actual content download failure remains unavailable and retains its request failure evidence'
    $securedNull = Get-ScimActionEvidence $absentContext $absentAction 'https://management.azure.com/secured' $false @('outputs') 'Compose'
    Assert-Report ($securedNull.contentAvailability.outputs.status -eq 'SecurityExcluded') 'Protected null or absent payloads remain security exclusions rather than collected values'
    $cachedNullContext = @{ secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); reusedPayloadCount = 0
        request = { throw 'Collected null unexpectedly requested a download.' }
        cachedActions = @{ 'https://management.azure.com/value' = @{
            status = 'Succeeded'; outputs = $null; contentAvailability = @{ outputs = @{ status = 'Collected' } }
        } }
    }
    $cachedNull = Get-ScimActionEvidence $cachedNullContext $absentAction 'https://management.azure.com/value' $false @() 'Compose'
    Assert-Report ($cachedNullContext.failures.Count -eq 0 -and $cachedNullContext.reusedPayloadCount -eq 1 -and $cachedNull.contentAvailability.outputs.status -eq 'ReusedSanitized' -and $null -eq $cachedNull.outputs) 'A previously proven collected JSON null is reusable without refetching or becoming unavailable'

    $listedCalls = [System.Collections.Generic.List[string]]::new()
    $skippedRepetitions = @(0..60 | ForEach-Object { @{
        name = [string]$_; properties = @{
            status = 'Skipped'; code = 'ActionSkipped'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:00Z'
            error = @{ code = 'BranchNotExecuted'; message = 'fixture-opaque-secret+/=42' }
            repetitionIndexes = @(@{ scopeName = 'Until'; itemIndex = $_ })
        }
    } })
    $listedContext = @{
        secrets = @($secret); failures = [System.Collections.Generic.List[object]]::new(); cachedActions = @{}
        requestMetricsEnabled = $true; requestMetrics = @{}; completedRepetitionCount = 0
        request = {
            param($uri, $arm)
            $listedCalls.Add($uri)
            if ($uri -match '/repetitions\?') { return @{ value = $skippedRepetitions } }
            throw 'Unexpected detail or payload request for skipped repetition.'
        }.GetNewClosure()
    }
    $listedAction = @{ name = 'Acquire_Token_Skipped'; properties = @{ status = 'Skipped'; code = 'ActionSkipped' } }
    $listedEvidence = Get-ScimActionEvidence $listedContext $listedAction 'https://management.azure.com/action' $true @() 'Workflow'
    Assert-Report ($listedEvidence.repetitions.Count -eq 61 -and $listedCalls.Count -eq 1 -and $listedContext.failures.Count -eq 0) 'All 61 skipped repetitions are retained with one listing and no redundant detail or payload requests'
    Assert-Report (@($listedEvidence.repetitions | Where-Object metadataSource -eq 'RepetitionListing').Count -eq 61) 'Skipped repetition listing provenance is explicit'
    Assert-Report ($listedEvidence.repetitions[0].contentAvailability.outputs.status -eq 'NotExecuted' -and $listedEvidence.repetitions[0].timing.durationMilliseconds -eq 0) 'Skipped repetitions explicitly have no execution payload while preserving supplied timing'
    Assert-Report ($listedEvidence.repetitions[0].evidence.properties.error.code -eq 'BranchNotExecuted' -and -not (ConvertTo-ScimCanonicalJson $listedEvidence).Contains($secret)) 'Skipped listing errors and repetition indexes are retained with credential redaction'
    Assert-Report ($listedContext.requestMetrics.RepetitionList.count -eq 1 -and -not $listedContext.requestMetrics.Contains('RepetitionDetail')) 'Request diagnostics distinguish listing work from avoided detail requests'
    $completeListed = @{ name = '0'; properties = @{
        status = 'Failed'; code = 'BadRequest'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
        error = @{ code = 'ObservedFailure'; message = 'Explicit failed probe.' }
        inputs = @{ method = 'GET' }; outputsLink = @{ uri = 'https://fixture.azure.com/listed-output' }
    } }
    $listingCalls = [System.Collections.Generic.List[string]]::new()
    $fullListedContext = @{
        secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); cachedActions = @{}
        request = {
            param($uri, $arm)
            $listingCalls.Add($uri)
            if ($uri -match '/repetitions\?') { return @{ value = @($completeListed) } }
            if ($uri -eq 'https://fixture.azure.com/listed-output') { return @{ statusCode = 400; body = @{ result = 'FAILED' } } }
            throw 'Complete listing unexpectedly requested repetition details.'
        }.GetNewClosure()
    }
    $fullListedEvidence = Get-ScimActionEvidence $fullListedContext @{ name = 'Http'; properties = @{ status = 'Failed'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z' } } 'https://management.azure.com/http' $true @() 'Http'
    Assert-Report ($fullListedEvidence.repetitions.Count -eq 1 -and $listingCalls.Count -eq 2 -and $fullListedContext.failures.Count -eq 0) 'Complete executed listing reuses metadata while still collecting the actual linked payload'
    Assert-Report ($fullListedEvidence.repetitions[0].outputs.statusCode -eq 400 -and $fullListedEvidence.repetitions[0].evidence.properties.error.code -eq 'ObservedFailure') 'Reused listing does not truncate failed execution evidence'
    $completeListed.properties.Remove('outputsLink')
    $listingCalls.Clear()
    $fullListedContext.request = {
        param($uri, $arm)
        $listingCalls.Add($uri)
        if ($uri -match '/repetitions\?') { return @{ value = @($completeListed) } }
        if ($uri -match '/repetitions/0\?') {
            $detail = @{ name = '0'; properties = $completeListed.properties.Clone() }
            $detail.properties.outputs = @{ statusCode = 400; body = @{ result = 'FAILED' } }
            return $detail
        }
        throw 'Unexpected incomplete-listing fixture request.'
    }.GetNewClosure()
    $detailEvidence = Get-ScimActionEvidence $fullListedContext @{ name = 'Http'; properties = @{ status = 'Failed'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z' } } 'https://management.azure.com/http' $true @() 'Http'
    Assert-Report ($detailEvidence.repetitions[0].metadataSource -eq 'RepetitionDetail' -and $listingCalls.Count -eq 2 -and $detailEvidence.repetitions[0].outputs.statusCode -eq 400) 'Incomplete executed listing still fetches details rather than treating missing evidence as complete'
    $pollCalls = [System.Collections.Generic.List[string]]::new()
    $pollRepetitions = @(0..60 | ForEach-Object {
        $props = @{
            status = if ($_ -eq 60) { 'Failed' } else { 'Succeeded' }
            startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
            inputsLink = @{ uri = "https://fixture.azure.com/poll/$_/inputs" }
            outputsLink = @{ uri = "https://fixture.azure.com/poll/$_/outputs" }
            repetitionIndexes = @(@{ scopeName = 'Poll_Until'; itemIndex = $_ })
            retryHistory = @(@{ code = 'RetryObserved'; statusCode = 429 })
        }
        if ($_ -eq 60) {
            $props.code = 'BadRequest'; $props.error = @{ code = 'NestedPollFailure'; message = 'Failure access_token=raw-poll-error' }
        }
        @{ name = [string]$_; properties = $props }
    })
    $pollContext = @{
        secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); cachedActions = @{}
        request = {
            param($uri, $arm)
            $pollCalls.Add($uri)
            if ($uri -match '/repetitions\?') { return @{ value = $pollRepetitions } }
            if ($uri -eq 'https://fixture.azure.com/poll/60/inputs') { return @{ method = 'GET'; uri = 'https://scim.example.invalid/Users'; headers = @{ Authorization = 'Bearer raw-poll-auth' } } }
            if ($uri -eq 'https://fixture.azure.com/poll/60/outputs') { return @{ statusCode = 400; body = @{ message = 'Failed poll response'; password = 'raw-poll-password' } } }
            if ($uri -eq 'https://fixture.azure.com/top-inputs') { return @{ method = 'GET'; uri = 'https://scim.example.invalid/Users' } }
            if ($uri -eq 'https://fixture.azure.com/top-outputs') { return @{ statusCode = 200; body = @{ Resources = @() } } }
            throw 'Successful poll repetition unexpectedly requested payload or detail.'
        }.GetNewClosure()
    }
    $pollAction = @{ name = 'Poll_Users'; properties = @{
        status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:01:01Z'
        inputsLink = @{ uri = 'https://fixture.azure.com/top-inputs' }; outputsLink = @{ uri = 'https://fixture.azure.com/top-outputs' }
    } }
    $pollEvidence = Get-ScimActionEvidence $pollContext $pollAction 'https://management.azure.com/poll' $true @() 'Http'
    Assert-Report ($pollEvidence.repetitions.Count -eq 61 -and $pollContext.failures.Count -eq 0) 'Failure-focused scope retains all sixty successful poll repetitions and the failed repetition without evidence gaps'
    Assert-Report ($pollCalls.Count -eq 5 -and @($pollCalls | Where-Object { $_ -match '/poll/\d+/(inputs|outputs)$' }).Count -eq 2) 'Sixty successful repetitions issue zero of their 120 payload GETs; exactly one failed repetition still fetches both payloads, alongside top-level payloads and one listing'
    Assert-Report (-not @($pollCalls | Where-Object { $_ -match '/repetitions/\d+\?' }).Count) 'Successful full listing timing/status is sufficient without repetition detail GETs'
    $successfulPolls = @($pollEvidence.repetitions | Where-Object status -eq 'Succeeded')
    Assert-Report (@($successfulPolls | Where-Object { $_.timing.durationMilliseconds -eq 1000 -and $_.contentAvailability.inputs.status -eq 'NotCollectedByScope' -and $_.contentAvailability.outputs.status -eq 'NotCollectedByScope' }).Count -eq 60) 'Every successful poll retains exact timing and explicitly declares omitted request/response bytes'
    Assert-Report ($successfulPolls[0].evidence.properties.retryHistory[0].statusCode -eq 429 -and $successfulPolls[0].evidence.properties.repetitionIndexes.Count -eq 1) 'Successful poll retry errors and loop indexes are not discarded with payloads'
    $failedPoll = @($pollEvidence.repetitions | Where-Object status -eq 'Failed')[0]
    Assert-Report ($failedPoll.inputs.method -eq 'GET' -and $failedPoll.outputs.statusCode -eq 400 -and $failedPoll.evidence.properties.error.code -eq 'NestedPollFailure') 'Failed poll retains sanitized request, response body, status and nested error evidence'
    Assert-Report ($pollEvidence.outputs.statusCode -eq 200 -and $pollEvidence.payloadCollection -eq 'TopLevelDiagnosticPayloads') 'Successful top-level action payloads remain in scope'
    Assert-Report (-not (ConvertTo-ScimCanonicalJson $pollEvidence).Contains('raw-poll-')) 'Failure-focused collection preserves credential redaction for failed poll payloads and errors'
    Assert-Report (Test-ScimRepetitionPayloadRequired 'Compose' 'Final_TestResults' @{ status = 'Succeeded' }) 'Successful semantic Compose repetitions remain payload-bearing'
    Assert-Report (Test-ScimRepetitionPayloadRequired 'Workflow' 'Call_Child' @{ status = 'Succeeded' }) 'Successful child calls retain payloads needed for exact child-run discovery'
    Assert-Report (Test-ScimRepetitionPayloadRequired 'Http' 'Probe' @{ status = 'Succeeded'; outputs = @{ body = @{ testResult = 'FAILED' } } }) 'Explicit semantic results remain in scope even when runtime status succeeded'
    Assert-Report (Test-ScimRepetitionPayloadRequired 'Http' 'Probe' @{ status = 'TimedOut' }) 'Timed-out repetition payloads are never excluded by the successful-poll scope'
    $semanticCacheContext = @{
        secrets = @(); failures = [System.Collections.Generic.List[object]]::new(); reusedPayloadCount = 0
        cachedActions = @{ 'https://management.azure.com/poll/repetitions/known-semantic' = @{
            status = 'Succeeded'; inputs = @{ method = 'GET' }; outputs = @{ body = @{ result = 'FAILED' } }
            contentAvailability = @{ inputs = @{ status = 'Collected' }; outputs = @{ status = 'Collected' } }
        } }
        request = { throw 'Previously collected semantic payload unexpectedly requested network access.' }
    }
    $semanticCached = Get-ScimActionEvidence $semanticCacheContext @{ name = 'known-semantic'; properties = @{
        status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
    } } 'https://management.azure.com/poll/repetitions/known-semantic' $false @() 'Http' -IsRepetition -RepetitionActionName 'Poll_Users'
    Assert-Report ($semanticCached.semanticResult -eq 'FAILED' -and $semanticCacheContext.reusedPayloadCount -eq 2 -and $semanticCacheContext.failures.Count -eq 0) 'Resume preserves previously collected semantic-failure payloads even for successful HTTP repetitions whose current listing omits links'
    $missingPollContext = $pollContext.Clone()
    $missingPollContext.failures = [System.Collections.Generic.List[object]]::new()
    [void](Get-ScimActionEvidence $missingPollContext @{ name = '60'; properties = @{
        status = 'TimedOut'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'
    } } 'https://management.azure.com/poll/repetitions/60' $false @() 'Http' -IsRepetition -RepetitionActionName 'Poll_Users')
    Assert-Report ($missingPollContext.failures.Count -eq 2) 'Unavailable timed-out repetition request and response are required evidence failures rather than intentional exclusions'
    $loopCheckpointPath = Join-Path $fixtureDirectory 'loop-checkpoint.json'
    $loopWorkflow = @{ name = 'Fixture_Workflow'; runId = 'fixture-loop-run'; actions = @() }
    $loopReport = @{ workflows = @($loopWorkflow); runtime = @{}; metadata = $secret }
    $loopContext = $listedContext.Clone()
    $loopContext.report = $loopReport; $loopContext.checkpointPath = $loopCheckpointPath
    $loopContext.activeWorkflow = $loopWorkflow; $loopContext.activeActionUri = 'https://management.azure.com/action'
    $loopContext.completedRepetitionCount = 0; $loopContext.lastCheckpointUtc = [datetimeoffset]::UtcNow.AddSeconds(-31)
    $loopInterrupted = $null
    try {
        function Write-Progress { param($Activity, $Status, [switch] $Completed) throw 'Fixture repetition checkpoint interruption.' }
        [void](Get-ScimActionEvidence $loopContext $listedAction 'https://management.azure.com/action' $true @() 'Workflow')
    } catch { $loopInterrupted = $_.Exception.Message }
    finally { Remove-Item Function:\Write-Progress -ErrorAction SilentlyContinue }
    $loopCheckpoint = Get-Content -LiteralPath $loopCheckpointPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($loopInterrupted -match 'repetition checkpoint interruption' -and $loopCheckpoint.workflows[0].actions[0].repetitions.Count -eq 1) 'A long action checkpoints its first completed repetition once the interval expires, without waiting for ten slow requests'
    Assert-Report ($loopCheckpoint.collection.completedActionCount -eq 0 -and $loopCheckpoint.collection.completedRepetitionCount -eq 1 -and -not $loopCheckpoint.galleryReadiness.ready) 'Partial repetition progress is distinguished from completed actions and never claims readiness'
    Assert-Report (-not (Get-Content -LiteralPath $loopCheckpointPath -Raw).Contains($secret)) 'Incremental repetition checkpoint sanitizes metadata and all collected repetition evidence'
    $loopContext.completedRepetitionCount = 20
    Save-ScimCollectionCheckpoint $loopContext $loopReport $loopCheckpointPath -RepetitionUpdate
    $batchedLoopCheckpoint = Get-Content -LiteralPath $loopCheckpointPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($batchedLoopCheckpoint.collection.completedRepetitionCount -eq 1) 'Rapid repetitions do not repeatedly rewrite a growing checkpoint before the thirty-second interval'
    Save-ScimCollectionCheckpoint $loopContext $loopReport $loopCheckpointPath -Force
    $forcedLoopCheckpoint = Get-Content -LiteralPath $loopCheckpointPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($forcedLoopCheckpoint.collection.completedRepetitionCount -eq 20) 'Workflow-boundary forced checkpoint persists progress regardless of the batching interval'
    Remove-Item -LiteralPath $loopCheckpointPath
    $snapshot = Get-ScimSanitizedReportSnapshot $loopReport @($secret)
    Assert-Report ([object]::ReferenceEquals($snapshot.workflows, $loopReport.workflows) -and $snapshot.metadata -eq '[REDACTED]') 'Checkpoint sanitizes new report metadata without rescanning the already-sanitized workflow inventory'

    $actionProperties = @{ status = 'Succeeded'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:02Z' }
    $workflowNames = @('Orchestrator_Workflow', 'Initialization_Workflow', 'UserTests_Workflow', 'GroupTests_Workflow', 'SCIMTests_Workflow', 'SCIMToken_Workflow', 'Authentication_Workflow')
    foreach ($wfName in $workflowNames) {
        $actions = @{}
        if ($wfName -eq 'Orchestrator_Workflow') {
            foreach ($child in $workflowNames | Where-Object { $_ -notin @('Orchestrator_Workflow', 'SCIMToken_Workflow', 'Authentication_Workflow') }) {
                $actions["Call_$child"] = @{ type = 'Workflow'; inputs = @{ host = @{ workflow = @{ id = $child } } } }
            }
            $actions.Final_TestResults = @{ type = 'Compose'; inputs = @{ testResults = @(
                @{ testName = 'Create_User_Test' }, @{ testName = 'OAuth2_Client_Credentials_Test' },
                @{ testName = 'Workload_Identity_Federation_Test' }
            ) } }
        } elseif ($wfName -eq 'UserTests_Workflow') {
            $actions.Create_User_Test = @{ type = 'Scope'; actions = @{} }
            $actions.Loop = @{ type = 'Foreach'; actions = @{ Nested_Failure = @{ type = 'Http' } } }
            $actions.Loop.actions.Call_Auth = @{ type = 'Workflow'; inputs = @{ host = @{ workflow = @{ id = 'SCIMToken_Workflow' } } } }
            $actions.Loop.actions.Nested_Until = @{ type = 'Until'; actions = @{
                Call_Secure_Auth = @{
                    type = 'Workflow'; inputs = @{ host = @{ workflow = @{ id = 'SCIMToken_Workflow' } } }
                    runtimeConfiguration = @{ secureData = @{ properties = @('inputs', 'outputs') } }
                }
            } }
            $actions.Standalone_Until = @{ type = 'Until'; actions = @{ Until_Poll = @{ type = 'Http' } } }
        } elseif ($wfName -eq 'SCIMTests_Workflow') {
            $actions.Call_Authentication = @{ type = 'Workflow'; inputs = @{ host = @{ workflow = @{ id = 'Authentication_Workflow' } } } }
        } elseif ($wfName -eq 'SCIMToken_Workflow') {
            $actions.Token_Request = @{ type = 'Http'; runtimeConfiguration = @{ secureData = @{ properties = @('inputs', 'outputs') } } }
        }
        @{ definition = @{ actions = $actions } } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $fixtureDirectory "$wfName.json")
    }
    $agentPath = Join-Path $fixtureDirectory 'agent.md'
    Set-Content -LiteralPath $agentPath -Value 'Offline fixture agent'
    $versionPath = Join-Path $fixtureDirectory 'VERSION'
    Set-Content -LiteralPath $versionPath -Value '14.0'
    # A self-contained source repository proves provenance without depending on parent edits.
    & git -C $fixtureDirectory init --quiet
    & git -C $fixtureDirectory add --all
    & git -C $fixtureDirectory -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --quiet -m 'Offline reporting fixture'
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git initialization failed.' }

    $state = @{
        core = 'PASSED'; oauth = 'PASSED'; wif = 'PASSED'; overall = 'PASSED'; auth = 'PASSED'; bearer = $null; version = $null; policy = $null; selected = $null; omitWif = $false
        deny = $false; omitCore = $false; omitAuth = $false; omitCorrelation = $false
        calls = [System.Collections.Generic.List[string]]::new()
    }
    $request = {
        param($uri, $arm)
        $state.calls.Add($uri)
        if ($state.deny -and $uri -match 'GroupTests_Workflow/runs') { throw '403 Forbidden client_secret=raw-live-denied' }
        if ($uri -match '/sites/[^/]+\?') { return @{ identity = @{ type = 'SystemAssigned'; principalId = 'fixture-principal' } } }
        if ($uri -match '/SCIMToken_Workflow/runs\?') {
            return @{ value = @(@{ name = 'exact-auth-secure-first'; properties = @{ correlation = @{ clientTrackingId = 'fixture-tracking' } } }); nextLink = 'https://management.azure.com/token-run-page2' }
        }
        if ($uri -eq 'https://management.azure.com/token-run-page2') {
            return @{ value = @(@{ name = 'exact-auth-secure-second'; properties = @{ correlation = @{ clientTrackingId = 'fixture-tracking' } } }) }
        }
        if ($uri -match '/actions/Call_(?:Secure_)?Auth/repetitions/([01])\?') {
            $index = $Matches[1]
            $props = $actionProperties.Clone()
            if ($uri -match '/Call_Secure_Auth/') {
                $props.outputs = @{ body = 'raw-secured-repetition-body' }
                $props.outputsLink = @{ uri = 'https://fixture.azure.com/forbidden-secure-repetition' }
            } else {
                $props.outputs = @{ headers = @{ 'x-ms-workflow-run-id' = "exact-auth-$index" } }
            }
            return @{ name = $index; properties = $props }
        }
        if ($uri -match '/actions/Call_(?:Secure_)?Auth/repetitions\?') { return @{ value = @(@{ name = '0' }, @{ name = '1' }) } }
        if ($uri -match '/(?:scopeRepetitions|repetitions)/0\?') {
            return @{ name = '0'; properties = @{ status = 'Failed'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'; inputs = @{ method = 'GET'; uri = 'https://scim.example.invalid/Users' }; error = @{ code = 'FixtureFailure'; message = 'api_key=raw-repetition-secret' }; outputsLink = @{ uri = 'https://fixture.azure.com/repetition?sig=raw-repetition-sas' } } }
        }
        if ($uri -match '/(?:scopeRepetitions|repetitions)\?') { return @{ value = @(@{ name = '0' }) } }
        if ($uri -match '^https://fixture.azure.com/repetition') { return @{ statusCode = 500; body = @{ message = 'Nested failure'; password = 'raw-body-password' }; headers = @{ Authorization = 'Bearer raw-output-header'; 'x-ms-request-id' = 'repetition-correlation' } } }
        if ($uri -match '/actions\?') {
            $wf = [regex]::Match($uri, '/workflows/([^/]+)/').Groups[1].Value
            $list = [System.Collections.Generic.List[object]]::new()
            if ($wf -eq 'Orchestrator_Workflow') {
                foreach ($child in $workflowNames | Where-Object { $_ -notin @('Orchestrator_Workflow', 'SCIMToken_Workflow', 'Authentication_Workflow') }) {
                    $props = $actionProperties.Clone(); $props.outputs = @{ headers = @{ 'x-ms-workflow-run-id' = "exact-$child" } }
                    $list.Add(@{ name = "Call_$child"; properties = $props })
                }
                $props = $actionProperties.Clone()
                $props.outputs = @{
                    overallResult = $state.overall; authenticationModelResult = $state.auth
                    testResults = @(
                        @{ testName = 'Create_User_Test'; testCategory = 'Mandatory'; testResult = $state.core },
                        @{ testName = 'OAuth2_Client_Credentials_Test'; testCategory = 'Authentication'; testResult = $state.oauth },
                        @{ testName = 'Workload_Identity_Federation_Test'; testCategory = 'Authentication'; testResult = $state.wif }
                    )
                }
                if ($state.bearer) { $props.outputs.BearerConnectivityTestOutputs = @{ overallResult = $state.bearer; result = $state.bearer } }
                if ($state.version) { $props.outputs.logicAppVersion = $state.version }
                if ($state.policy) { $props.outputs.authenticationPolicy = $state.policy }
                if ($state.selected) { $props.outputs.supportedAuthenticationMethods = $state.selected }
                if ($state.omitWif) { $props.outputs.testResults = @($props.outputs.testResults | Where-Object testName -ne 'Workload_Identity_Federation_Test') }
                if ($state.omitCore) { $props.outputs.testResults = @($props.outputs.testResults | Where-Object testName -ne 'Create_User_Test') }
                if ($state.omitAuth) { $props.outputs.Remove('authenticationModelResult') }
                $list.Add(@{ name = 'Final_TestResults'; properties = $props })
            } elseif ($wf -eq 'UserTests_Workflow') {
                $list.Add(@{ name = 'Create_User_Test'; properties = $actionProperties.Clone() })
                $list.Add(@{ name = 'Loop'; properties = $actionProperties.Clone() })
                $list.Add(@{ name = 'Nested_Failure'; properties = $actionProperties.Clone() })
                $untilProperties = $actionProperties.Clone(); $untilProperties.iterationCount = 1
                $list.Add(@{ name = 'Standalone_Until'; properties = $untilProperties })
                $list.Add(@{ name = 'Until_Poll'; properties = $actionProperties.Clone() })
                $props = $actionProperties.Clone()
                $list.Add(@{ name = 'Call_Auth'; properties = $props })
                $props = $actionProperties.Clone(); $props.outputs = @{ body = 'raw-secured-call-body' }
                $props.outputsLink = @{ uri = 'https://fixture.azure.com/forbidden-secure-call' }
                $list.Add(@{ name = 'Call_Secure_Auth'; properties = $props })
            } elseif ($wf -eq 'SCIMToken_Workflow') {
                $props = $actionProperties.Clone()
                $props.inputs = @{ body = 'raw-secure-input' }; $props.outputs = @{ body = 'raw-secure-output' }
                $props.inputsLink = @{ uri = 'https://fixture.azure.com/forbidden-secure-input' }
                $props.outputsLink = @{ uri = 'https://fixture.azure.com/forbidden-secure-output' }
                $props.retryHistory = @(@{ statusCode = 429; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:01Z'; body = 'raw-secured-retry-body' })
                $props.error = @{ code = 'FixtureTokenRetry'; message = 'raw-secured-token-error' }
                $list.Add(@{ name = 'Token_Request'; properties = $props })
            } elseif ($wf -eq 'SCIMTests_Workflow') {
                $props = $actionProperties.Clone(); $props.outputs = @{ headers = @{ 'x-ms-workflow-run-id' = 'exact-authentication' } }
                $list.Add(@{ name = 'Call_Authentication'; properties = $props })
            } else { $list.Add(@{ name = 'Compose_Result'; properties = $actionProperties.Clone() }) }
            return @{ value = @($list) }
        }
        if ($uri -match '/runs/[^/]+\?') {
            $p = $actionProperties.Clone()
            if (-not $state.omitCorrelation) { $p.correlation = @{ clientTrackingId = 'fixture-tracking' } }
            if ($uri -match 'exact-auth-1\?') { $p.error = @{ code = 'RetryObserved'; message = 'Token retry evidence access_token=raw-child-error-token' } }
            $p.trigger = @{ name = 'manual'; status = 'Succeeded'; startTime = $p.startTime; endTime = $p.endTime }
            return @{ name = ([regex]::Match($uri, '/runs/([^?]+)').Groups[1].Value); properties = $p }
        }
        throw "Unexpected offline request: $uri"
    }.GetNewClosure()
    $metadata = @{
        supportedAuthenticationMethods = @('OAuth2ClientCredentials', 'WorkloadIdentityFederation')
        source = @{ revision = 'caller-source-revision'; repositoryUrl = 'https://example.invalid/repository'; ignored = 'raw-ignored-source' }
        deploymentOverlay = @{ name = 'fixture-overlay'; sha256 = ('a' * 64); ignored = 'raw-ignored-overlay'; workflowHashes = @(@{ name = 'SCIMToken_Workflow'; sha256 = ('b' * 64) }) }
        harness = @{ name = 'offline fixture'; model = $null; reasoning = $null; context = $null }
    }
    $reportArgs = @{
        SubscriptionId = 'fixture-subscription'; ResourceGroupName = 'fixture-group'; LogicAppName = 'fixture-app'
        OrchestratorRunId = 'exact-orchestrator'; AgentPath = $agentPath; WorkflowDirectory = $fixtureDirectory
        Metadata = $metadata; Request = $request; WorkDirectory = $fixtureDirectory
    }
    $report = New-ScimValidationReport @reportArgs
    Assert-Report $report.completeness.complete 'All required fake evidence collected'
    Assert-Report ($report.diagnosticScope.name -eq 'FailureFocused' -and $report.completeness.scope.Contains('NotCollectedByScope') -and $report.completeness.scope.Contains('never claims every payload')) 'Report explicitly defines completeness within failure-focused diagnostic scope rather than claiming every successful poll payload'
    Assert-Report $report.galleryReadiness.ready 'Every selected gallery authentication method passes'
    Assert-Report ($report.provenance.sourceVersion.value -eq '14.0' -and $report.provenance.agent.sourceVersion -eq '14.0') 'Overall and agent source versions come only from VERSION'
    Assert-Report ($report.provenance.sourceVersion.sha256 -eq (Get-FileHash $versionPath).Hash.ToLowerInvariant()) 'VERSION exact bytes are hashed for source provenance'
    Assert-Report ($null -eq $report.provenance.executedVersion.value -and $null -eq $report.provenance.comparison.deployedVersionMatchesSource) 'Unknown historical deployment is never rebranded with the current source version'
    $historicalArgs = $reportArgs.Clone(); $historicalArgs.Metadata = $metadata.Clone()
    $historicalArgs.Metadata.historicalRun = @{ version = '11.0'; sourceVersion = @{ value = '13.0'; sha256 = ('c' * 64) }; authenticationPolicy = 'AnySelected'; selectedMethods = @('OAuth2ClientCredentials', 'WorkloadIdentityFederation') }
    $historicalReport = New-ScimValidationReport @historicalArgs
    Assert-Report ($historicalReport.provenance.executedVersion.value -eq '11.0' -and $historicalReport.provenance.comparison.deployedVersionMatchesSource -eq $false) 'Historical deployed version and source version remain distinct with an explicit mismatch'
    Assert-Report ($historicalReport.historicalRun.metadata.authenticationPolicy -eq 'AnySelected') 'Historical OR policy remains intact alongside the current AND assessment'
    Assert-Report ($historicalReport.historicalRun.metadata.sourceVersion.value -eq '13.0' -and $historicalReport.historicalRun.metadata.sourceVersion.sha256 -eq ('c' * 64)) 'Original source VERSION and hash remain distinct from deployed version 11 and current reporting source 14'
    Assert-Report ($report.agentEvents.status -eq 'Unavailable' -and $report.agentEvents.unavailableReason) 'Historical reports explicitly lack optional agent events'
    Assert-Report ($report.agentRun.timingState -eq 'Unrecorded' -and $null -eq $report.agentRun.timing.durationMilliseconds) 'Unrecorded agent window receives no invented timing'
    Assert-Report ($report.workflows.Count -eq 10) "Discovers all seven workflow definitions and every repeated child (observed: $($report.workflows.runId -join ', '))"
    Assert-Report (@($report.workflows | Where-Object { $_.name -eq 'Authentication_Workflow' -and $_.runId -eq 'exact-authentication' }).Count -eq 1) 'Seventh synchronous authentication workflow is discovered through its nested exact child call'
    Assert-Report ($report.orchestratorRunId -eq 'exact-orchestrator') 'Exact orchestrator ID preserved'
    Assert-Report (@($report.workflows | Where-Object runId -eq 'exact-auth-0').Count -eq 1) 'First repeated nested child ID preserved'
    Assert-Report (@($report.workflows | Where-Object runId -eq 'exact-auth-1').Count -eq 1) 'Second repeated nested child ID preserved'
    Assert-Report (@($report.childRunAssociations | Where-Object { $_.parentActionName -eq 'Call_Auth' -and $_.repetitionName -eq '1' }).Count -eq 1) 'Exact repetition association preserved'
    Assert-Report (@($report.workflows | Where-Object { $_.runId -eq 'exact-auth-secure-second' -and $_.discovery -match 'Correlation-only' }).Count -eq 1) 'Secured correlation inventory is explicitly not an exact parent mapping'
    Assert-Report (@($report.workflows | Where-Object runId -eq 'exact-auth-1')[0].timing.durationMilliseconds -eq 2000) 'Nested child timing collected'
    Assert-Report (@($report.workflows | Where-Object runId -eq 'exact-auth-1')[0].run.properties.error.code -eq 'RetryObserved') 'Nested child error retained safely'
    Assert-Report ($report.completeness.securityExcludedCount -gt 0 -and $report.securityExclusions.Count -eq 1) 'Secured child evidence is excluded, not falsely incomplete'
    Assert-Report ($report.suppliedSource.metadata.revision -eq 'caller-source-revision' -and $report.provenance.sourceGit.revision -ne 'caller-source-revision') 'Caller source claims do not override observed source revision'
    Assert-Report ($report.deploymentOverlay.metadata.workflowHashes[0].sha256 -eq ('b' * 64)) 'Allowlisted deployment-overlay hashes retained'
    Assert-Report ($report.provenance.agent.sha256 -eq (Get-FileHash $agentPath).Hash.ToLowerInvariant()) 'Agent SHA256'
    Assert-Report (-not $report.provenance.sourceGit.dirty) 'Clean source revision recorded'
    Assert-Report ($null -eq $report.harness.model.value -and $report.harness.model.unavailableReason) 'Unknown model has explicit reason'
    Assert-Report ($report.tests[0].scopeTimings.Count -eq 1) 'Test scope timing matched'
    $loop = @($report.workflows | Where-Object name -eq 'UserTests_Workflow')[0].actions | Where-Object name -eq 'Nested_Failure'
    Assert-Report ($loop.repetitions[0].status -eq 'Failed') 'Nested failure repetition retained'
    Assert-Report (-not @($state.calls | Where-Object { $_ -match '/Standalone_Until/(?:scopeRepetitions|repetitions)' }).Count) 'Until containers do not call runtime endpoints proven unsupported in live probes'
    Assert-Report (-not @($state.calls | Where-Object { $_ -match '/Nested_Until/(?:scopeRepetitions|repetitions)' }).Count) 'Nested Until containers also avoid unsupported container repetition endpoints'
    Assert-Report (@($state.calls | Where-Object { $_ -match '/Until_Poll/repetitions\?' }).Count -gt 0) 'Until child action repetitions remain fully collected'
    Assert-Report (@($state.calls | Where-Object { $_ -match '/Loop/scopeRepetitions\?' }).Count -gt 0) 'Foreach containers use the scopeRepetitions API'
    Assert-Report ($loop.repetitions[0].outputs.headers.'x-ms-request-id' -eq 'repetition-correlation') 'Repetition correlation retained'
    Assert-Report (-not @($state.calls | Where-Object { $_ -match 'forbidden-secure' }).Count) 'SecureData links never fetched'
    $protected = @($report.workflows | Where-Object name -eq 'SCIMToken_Workflow')[0].actions[0]
    Assert-Report ($protected.securityExclusions.Count -eq 2) 'SecureData exclusions explicitly recorded'
    Assert-Report ($protected.evidence.properties.retryHistory[0].statusCode -eq 429) 'Token-action safe retry status retained'
    Assert-Report ($protected.evidence.properties.error.code -eq 'FixtureTokenRetry') 'Token-action safe error code retained without protected error detail'
    Assert-Report ($loop.repetitions[0].evidence.properties.error.code -eq 'FixtureFailure') 'Structured error code retained'
    $serializedReport = ConvertTo-ScimCanonicalJson $report
    Assert-Report (-not $serializedReport.Contains('raw-')) 'No raw token/header/body/error/SAS fixture persisted'
    $second = New-ScimValidationReport @reportArgs
    Assert-Report ((ConvertTo-ScimCanonicalJson $second) -eq $serializedReport) 'Repeated export is deterministic'
    $resumeArgs = $reportArgs.Clone(); $resumeArgs.PreviousReport = $report
    $beforePayloadCalls = @($state.calls | Where-Object { $_ -match '^https://fixture.azure.com/repetition' }).Count
    $beforeRunCalls = @($state.calls | Where-Object { $_ -match '/runs/[^/]+\?' }).Count
    $resumed = New-ScimValidationReport @resumeArgs
    Assert-Report ($resumed.resume.reusedPayloadCount -gt 0 -and $resumed.completeness.complete) 'Terminal report resume reuses previously collected sanitized payloads'
    Assert-Report (@($state.calls | Where-Object { $_ -match '^https://fixture.azure.com/repetition' }).Count -eq $beforePayloadCalls) 'Resume does not re-download successful immutable payload links'
    Assert-Report (@($state.calls | Where-Object { $_ -match '/runs/[^/]+\?' }).Count -gt $beforeRunCalls) 'Resume still reads current run headers rather than replaying stale statuses'
    $partialPrevious = ConvertTo-ScimCanonicalJson $report | ConvertFrom-Json -AsHashtable
    $partialUser = @($partialPrevious.workflows | Where-Object name -eq 'UserTests_Workflow')[0]
    $partialAction = @($partialUser.actions | Where-Object name -eq 'Nested_Failure')[0]
    $partialAction.repetitions[0].outputs = $null
    $partialAction.repetitions[0].contentAvailability.outputs.status = 'Unavailable'
    $partialPrevious.evidenceFailures = @(@{ source = 'Old fixture failure'; reason = 'Old unavailable payload'; required = $true })
    $resumeArgs.PreviousReport = $partialPrevious
    $retriedResume = New-ScimValidationReport @resumeArgs
    Assert-Report (@($state.calls | Where-Object { $_ -match '^https://fixture.azure.com/repetition' }).Count -gt $beforePayloadCalls -and $retriedResume.completeness.complete) 'Resume retries previously missing payloads and recomputes failures'
    Assert-Report (-not @($retriedResume.evidenceFailures | Where-Object source -eq 'Old fixture failure').Count) 'Resume does not inherit obsolete evidence failures'
    $wrongResumeArgs = $resumeArgs.Clone(); $wrongResumeArgs.OrchestratorRunId = 'different-root'
    $wrongResumeReason = $null
    try { [void](New-ScimValidationReport @wrongResumeArgs) } catch { $wrongResumeReason = $_.Exception.Message }
    Assert-Report ($wrongResumeReason -match 'does not match') 'Resume refuses a different root or Azure site'
    $checkpointDirectory = Join-Path $fixtureDirectory 'interrupted'
    [void][IO.Directory]::CreateDirectory($checkpointDirectory)
    $checkpointPath = Join-Path $checkpointDirectory 'validation-run-details.checkpoint.json'
    $canonicalPath = Join-Path $checkpointDirectory 'validation-run-details.json'
    Set-Content -LiteralPath $canonicalPath -Value 'existing canonical report'
    $checkpointArgs = $reportArgs.Clone(); $checkpointArgs.CheckpointPath = $checkpointPath
    $checkpointFailure = $null
    try {
        function Write-Progress {
            param($Activity, $Status, [switch] $Completed)
            if (Test-Path -LiteralPath $checkpointPath) {
                $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json -AsHashtable
                if (@($saved.workflows | ForEach-Object { $_.actions | Where-Object name -eq 'Nested_Failure' }).Count) { throw 'Fixture collection interruption after checkpoint save.' }
            }
        }
        [void](New-ScimValidationReport @checkpointArgs)
    } catch { $checkpointFailure = $_.Exception.Message }
    finally { Remove-Item Function:\Write-Progress -ErrorAction SilentlyContinue }
    Assert-Report ($checkpointFailure -match 'Fixture collection interruption') 'A controlled interruption occurs after successful evidence is persisted'
    $savedCheckpoint = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($savedCheckpoint.collection.status -eq 'InProgress' -and -not $savedCheckpoint.completeness.complete -and $savedCheckpoint.galleryReadiness.exitCode -eq 2) 'Interrupted checkpoint never claims completeness or readiness'
    Assert-Report ($savedCheckpoint.provenance.sourceVersion.value -eq '14.0' -and $savedCheckpoint.orchestratorRunId -eq 'exact-orchestrator') 'Checkpoint carries source VERSION and exact original run identity'
    Assert-Report (-not (Get-Content -LiteralPath $checkpointPath -Raw).Contains('raw-')) 'Incremental checkpoint contains only sanitized evidence'
    Assert-Report ((Get-Content -LiteralPath $canonicalPath -Raw).Trim() -eq 'existing canonical report') 'Interrupted collection does not overwrite an existing canonical report'
    Assert-Report (-not (Test-Path -LiteralPath "$checkpointPath.pending")) 'Checkpoint replacement leaves no pending scratch file after successful save'
    $checkpointArgs.PreviousReport = $savedCheckpoint
    $checkpointResumed = New-ScimValidationReport @checkpointArgs
    Assert-Report ($checkpointResumed.completeness.complete -and $checkpointResumed.resume.reusedPayloadCount -gt 0) 'A partial interrupted checkpoint resumes successful payloads and completes all remaining evidence'
    Write-ScimValidationReport $report $fixtureDirectory -Zip
    foreach ($file in @('validation-run-details.json', 'validation-report.md', 'validation-report.zip')) {
        Assert-Report (Test-Path -LiteralPath (Join-Path $fixtureDirectory $file)) "Output created: $file"
    }
    Assert-Report (-not (Get-Content (Join-Path $fixtureDirectory 'validation-report.md') -Raw).Contains('raw-')) 'Human report sanitized'
    $agentEventsFile = Join-Path $fixtureDirectory 'agent-events.json'
    @(
        @{ name = 'Setup'; kind = 'setup'; parentName = 'Agent'; startTime = '2026-01-01T01:00:00+01:00'; endTime = '2026-01-01T00:00:03Z'; status = 'Succeeded'; details = @{ message = 'Configured endpoint'; client_secret = 'raw-agent-client-secret'; embedded = '{"access_token":"raw-agent-embedded-token"}'; literal = $secret } },
        @{ name = 'Cleanup'; kind = 'cleanup'; parentName = 'Agent'; startTime = '2026-01-01T00:00:04Z'; endTime = $null; status = 'Running'; details = 'Authorization: Bearer raw-agent-free-token' },
        @{ name = 'HistoricalStep'; kind = 'step'; parentName = $null; startTime = $null; endTime = $null; status = 'Unknown'; details = $null },
        @{ name = 'MissingStart'; kind = 'step'; parentName = $null; startTime = $null; endTime = '2026-01-01T00:00:05Z'; status = 'Succeeded'; details = $null },
        @{ name = 'InvalidTime'; kind = 'step'; parentName = $null; startTime = 'invalid'; endTime = 'invalid'; status = 'Failed'; details = 'client_secret=raw-agent-error-secret' }
    ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $agentEventsFile
    $metadata.agentEventsPath = 'agent-events.json'
    $metadata.agentRun = @{ startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:01:00Z'; status = 'Succeeded' }
    $eventArgs = $reportArgs.Clone(); $eventArgs.KnownSecrets = @($secret)
    $withEvents = New-ScimValidationReport @eventArgs
    Assert-Report ($withEvents.completeness.complete -and $withEvents.galleryReadiness.ready) 'Partial optional agent timings do not invalidate historical Azure evidence'
    Assert-Report ($withEvents.agentRun.timing.durationMilliseconds -eq 60000 -and $withEvents.fullRun.timing.durationMilliseconds -eq 2000) 'Agent window is separate from Azure Orchestrator window'
    Assert-Report ($withEvents.agentEvents.events[0].timing.durationMilliseconds -eq 3000) 'Explicit event elapsed time is calculated in UTC'
    Assert-Report ($withEvents.agentEvents.events[0].timing.startUtc -eq '2026-01-01T00:00:00.0000000Z') 'Agent event timestamps normalized to UTC'
    Assert-Report ($withEvents.agentEvents.events[1].timingState -eq 'Open' -and $null -eq $withEvents.agentEvents.events[1].timing.endUtc -and $null -eq $withEvents.agentEvents.events[1].timing.durationMilliseconds) 'Open agent event has no invented end or duration'
    Assert-Report ($withEvents.agentEvents.events[2].timingState -eq 'Unrecorded' -and $withEvents.agentEvents.events[2].timing.unavailableReason) 'Unrecorded event timing is explicit'
    Assert-Report ($withEvents.agentEvents.events[3].timingState -eq 'MissingStart') 'Missing event start is explicit'
    Assert-Report ($withEvents.agentEvents.events[4].timingState -eq 'Invalid') 'Invalid event timing is explicit'
    Assert-Report ($withEvents.agentEvents.openEventCount -eq 1 -and $withEvents.agentEvents.missingTimingCount -eq 2 -and $withEvents.agentEvents.invalidEventCount -eq 1) 'Partial agent event counters are accurate'
    $agentJson = ConvertTo-ScimCanonicalJson $withEvents
    Assert-Report (-not $agentJson.Contains('raw-agent-') -and -not $agentJson.Contains($secret)) 'Agent details and exact known literals are sanitized'
    Write-ScimValidationReport $withEvents $fixtureDirectory
    $agentMarkdown = Get-Content (Join-Path $fixtureDirectory 'validation-report.md') -Raw
    Assert-Report ($agentMarkdown.Contains('Agent and setup timing') -and $agentMarkdown.Contains('Cleanup') -and $agentMarkdown.Contains('Open')) 'Human report exposes agent and setup timing with open-event state'
    Assert-Report (-not $agentMarkdown.Contains('raw-agent-') -and -not $agentMarkdown.Contains($secret)) 'Human agent event details are sanitized'
    $agentContext = @{ failures = [System.Collections.Generic.List[object]]::new(); secrets = @($secret) }
    $missingEvents = Get-ScimAgentEvents $agentContext 'missing-agent-events.json' $fixtureDirectory
    Assert-Report ($missingEvents.status -eq 'Unavailable' -and $agentContext.failures.Count -eq 1 -and -not $agentContext.failures[0].required) 'Missing optional event file is explicitly unavailable and not required'
    $invalidEventsPath = Join-Path $fixtureDirectory 'invalid-agent-events.json'
    Set-Content -LiteralPath $invalidEventsPath -Value '{"not":"an array"}'
    $invalidEvents = Get-ScimAgentEvents $agentContext $invalidEventsPath $fixtureDirectory
    Assert-Report ($invalidEvents.status -eq 'Unavailable' -and $invalidEvents.unavailableReason -match 'JSON array') 'Agent event source requires a JSON array'
    Set-Content -LiteralPath $invalidEventsPath -Value '[]'
    Assert-Report ((Get-ScimAgentEvents $agentContext $invalidEventsPath $fixtureDirectory).status -eq 'Unavailable') 'Empty event array does not pretend recorded coverage'
    $openWindow = Get-ScimRecordedTiming @{ startTime = '2026-01-01T00:00:00Z'; status = 'Running' }
    Assert-Report ($openWindow.timingState -eq 'Open' -and $null -eq $openWindow.timing.durationMilliseconds) 'Open agent run window has no fabricated cleanup time'
    $ambiguousWindow = Get-ScimRecordedTiming @{ startTime = '2026-01-01T00:00:00'; endTime = '2026-01-01T00:01:00' }
    Assert-Report ($ambiguousWindow.timingState -eq 'Invalid' -and $null -eq $ambiguousWindow.timing.durationMilliseconds) 'Missing time zone is not guessed from the export machine'
    Set-Content -LiteralPath $invalidEventsPath -Value '[ raw-agent-malformed-payload'
    $malformedEvents = Get-ScimAgentEvents $agentContext $invalidEventsPath $fixtureDirectory
    Assert-Report ($malformedEvents.status -eq 'Unavailable' -and -not $malformedEvents.unavailableReason.Contains('raw-agent-malformed-payload')) 'Malformed agent JSON is diagnosed without echoing raw payload snippets'
    $metadata.Remove('agentRun'); $metadata.Remove('agentEventsPath')

    $state.wif = 'FAILED'
    $andFailure = New-ScimValidationReport @reportArgs
    Assert-Report (-not $andFailure.galleryReadiness.ready -and $andFailure.galleryReadiness.exitCode -eq 1) 'OAuth success cannot waive a selected failed federation method'
    Assert-Report ($andFailure.authentication.aggregatePolicyMismatch -and $andFailure.authentication.recordedAggregateResult -eq 'PASSED') 'Stale historical aggregate success remains visible but cannot override selected-method AND validation'
    Assert-Report ($andFailure.authentication.policy.Contains('static-token connectivity') -and -not $andFailure.authentication.policy.Contains('[REDACTED')) 'Authentication policy explanation stays readable without weakening credential redaction'
    Assert-Report ($andFailure.galleryReadiness.reason.Contains('Static-token connectivity alone') -and -not $andFailure.galleryReadiness.reason.Contains('[REDACTED')) 'Static-token-only readiness explanation is retained by the unchanged redactor'
    $metadata.applicability = @{ Workload_Identity_Federation_Test = @{ applicable = $false; reason = 'Attempted selected-method waiver' } }
    $state.wif = 'NOT_APPLICABLE - credentials missing'
    $selectedMissing = New-ScimValidationReport @reportArgs
    Assert-Report ($selectedMissing.galleryReadiness.exitCode -eq 2 -and @($selectedMissing.evidenceFailures | Where-Object source -eq 'Selected authentication method WorkloadIdentityFederation').Count -eq 1) 'Selected method with missing credentials or NA is a blocker despite a caller applicability waiver'
    $state.omitWif = $true
    $selectedAbsent = New-ScimValidationReport @reportArgs
    Assert-Report ($selectedAbsent.galleryReadiness.exitCode -eq 2 -and @($selectedAbsent.authentication.methodResults | Where-Object method -eq 'WorkloadIdentityFederation')[0].resultCount -eq 0) 'A selected method with no result is an explicit missing-evidence blocker'
    $state.omitWif = $false
    $metadata.Remove('applicability')
    $metadata.supportedAuthenticationMethods = @('OAuth2ClientCredentials')
    $state.wif = 'FAILED'
    $oauthOnly = New-ScimValidationReport @reportArgs
    Assert-Report ($oauthOnly.galleryReadiness.ready -and @($oauthOnly.tests | Where-Object authenticationMethod -eq 'WorkloadIdentityFederation')[0].classification -eq 'NotApplicable') 'Undeclared failed federation is not applicable while its original recorded result remains intact'
    Assert-Report (@($oauthOnly.tests | Where-Object authenticationMethod -eq 'WorkloadIdentityFederation')[0].semanticResult -eq 'FAILED') 'Historical semantic evidence is not rewritten when applicability changes'
    $state.selected = @('OAuth2ClientCredentials', 'WorkloadIdentityFederation')
    $selectionMismatch = New-ScimValidationReport @reportArgs
    Assert-Report ($selectionMismatch.authentication.selectionMismatch -and $selectionMismatch.galleryReadiness.exitCode -eq 2) 'Caller metadata cannot silently drop a selected failing method from recorded execution'
    $state.selected = $null
    $metadata.supportedAuthenticationMethods = @('Bearer', 'OAuth2ClientCredentials')
    $mixedMissing = New-ScimValidationReport @reportArgs
    Assert-Report ($mixedMissing.galleryReadiness.exitCode -eq 2) 'Selected static bearer with no connectivity probe evidence blocks a mixed-method report'
    $state.bearer = 'FAILED'
    Assert-Report ((New-ScimValidationReport @reportArgs).galleryReadiness.exitCode -eq 1) 'Failed bearer connectivity blocks otherwise passing selected OAuth'
    $state.bearer = 'PASSED'
    $mixedPassing = New-ScimValidationReport @reportArgs
    Assert-Report ($mixedPassing.galleryReadiness.ready -and $mixedPassing.authentication.methodResults.Count -eq 2) 'Mixed bearer and OAuth requires both the actual connectivity probe and gallery authentication test to pass'
    Assert-Report ($mixedPassing.tests.Count -eq 3 -and $mixedPassing.authentication.bearerConnectivity.overallResult -eq 'PASSED') 'Separate bearer probe does not change the historical named-test inventory'
    $metadata.supportedAuthenticationMethods = @('Bearer')
    Assert-Report (-not (New-ScimValidationReport @reportArgs).galleryReadiness.ready) 'A passing static bearer connectivity probe alone is still not gallery-ready'
    $state.bearer = $null; $state.wif = 'PASSED'
    $metadata.supportedAuthenticationMethods = @('OAuth2ClientCredentials', 'WorkloadIdentityFederation')
    $state.version = '14.0'; $state.policy = 'AllSelected'
    $currentRun = New-ScimValidationReport @reportArgs
    Assert-Report ($currentRun.provenance.executedVersion.value -eq '14.0' -and $currentRun.authentication.recordedPolicy -eq 'AllSelected' -and $currentRun.provenance.comparison.deployedVersionMatchesSource) 'New deployed outputs explicitly establish their own version and AllSelected policy'
    $state.version = $null; $state.policy = $null
    Remove-Item -LiteralPath $versionPath
    Assert-Report ((New-ScimValidationReport @reportArgs).galleryReadiness.exitCode -eq 2) 'Missing VERSION provenance blocks readiness instead of inventing a revision'
    Set-Content -LiteralPath $versionPath -Value '14.0'
    $state.core = 'FAILED raw-scope-semantic'
    $failedArgs = $reportArgs.Clone(); $failedArgs.KnownSecrets = @('raw-scope-semantic')
    $failed = New-ScimValidationReport @failedArgs
    Assert-Report (-not $failed.galleryReadiness.ready -and $failed.galleryReadiness.exitCode -eq 1) 'Succeeded runtime does not override failed semantic core test'
    Assert-Report (-not (ConvertTo-ScimCanonicalJson $failed).Contains('raw-scope-semantic')) 'Late scope semantic updates are sanitized before entering the reusable workflow inventory'
    $legacyFixture = ConvertTo-ScimCanonicalJson $failed | ConvertFrom-Json -AsHashtable
    $legacyEntry = @{
        name = '0'; type = 'Compose'; status = 'Succeeded'; collectionState = 'Completed'
        payloadCollection = 'RequiredDiagnosticRepetition'; inputs = ''; outputs = $null; securityExclusions = @()
        contentAvailability = @{ inputs = @{ status = 'Collected' }; outputs = @{ status = 'Unavailable' } }
        evidence = @{ properties = @{ outputsLink = @{ uri = 'https://fixture.azure.com/legacy-empty'; contentSize = 2 } } }
    }
    $legacyParent = @{ name = 'Compose_Legacy'; type = 'Compose'; status = 'Succeeded'; collectionState = 'Completed'
        repetitionCollection = @{ kind = 'repetitions' }; repetitions = @($legacyEntry) }
    @($legacyFixture.workflows | Where-Object name -eq 'Orchestrator_Workflow')[0].actions += $legacyParent
    $legacySource = 'https://management.azure.com/subscriptions/fixture-subscription/resourceGroups/fixture-group/providers/Microsoft.Web/sites/fixture-app/hostruntime/runtime/webhooks/workflow/api/management/workflows/Orchestrator_Workflow/runs/exact-orchestrator/actions/Compose_Legacy/repetitions/0/outputs'
    $legacyFixture.evidenceFailures += @{ source = $legacySource; reason = 'Successful data-producing action supplied no readable output evidence.'; required = $true }
    $legacyFixture.runtime.evidenceRequests = @{ ContentPayload = @{ count = 1; failed = 0 } }
    $legacyFixture.completeness.complete = $false; $legacyFixture.completeness.requiredUnavailableCount = 1
    $legacyFixture.galleryReadiness.status = 'Incomplete'; $legacyFixture.galleryReadiness.exitCode = 2
    $legacyPath = Join-Path $fixtureDirectory 'legacy-empty-report.json'
    [IO.File]::WriteAllText($legacyPath, (ConvertTo-ScimCanonicalJson $legacyFixture), [Text.UTF8Encoding]::new($false))
    $legacyHash = (Get-FileHash -LiteralPath $legacyPath).Hash.ToLowerInvariant()
    $offline = Complete-ScimValidationReport -ReportPath $legacyPath
    Assert-Report ($offline.offlineFinalization.correctedOutputCount -eq 1 -and $offline.offlineFinalization.networkRequests -eq 0 -and $offline.completeness.complete) 'Offline finalization repairs the proven empty-string classification without recollection'
    Assert-Report ($offline.galleryReadiness.status -eq 'NotReady' -and $offline.galleryReadiness.exitCode -eq 1 -and -not $offline.galleryReadiness.ready) 'Correcting collection completeness never waives recorded functional failures or establishes readiness'
    $offlineEntry = @(@($offline.workflows | Where-Object name -eq 'Orchestrator_Workflow')[0].actions | Where-Object name -eq 'Compose_Legacy')[0].repetitions[0]
    Assert-Report ($offlineEntry.outputs -is [string] -and $offlineEntry.outputs.Length -eq 0 -and $offlineEntry.contentAvailability.outputs.presenceSource -eq 'OfflineComposeIdentityCorrection') 'Offline proof restores an empty string, not an invented JSON null or success result'
    Assert-Report ((Get-FileHash -LiteralPath $legacyPath).Hash.ToLowerInvariant() -eq $legacyHash -and $offline.offlineFinalization.sourceReportSha256 -eq $legacyHash) 'Offline finalization reads the source report immutably and records its exact SHA256'
    Assert-Report ((ConvertTo-ScimCanonicalJson $offline.provenance) -eq (ConvertTo-ScimCanonicalJson $legacyFixture.provenance) -and
        (ConvertTo-ScimCanonicalJson $offline.tests) -eq (ConvertTo-ScimCanonicalJson $legacyFixture.tests)) 'Offline finalization preserves historical/source provenance and every original semantic test result'
    Assert-Report ($offline.offlineFinalization.corrector.fileName -eq 'Export-ScimValidationReport.ps1' -and
        $offline.offlineFinalization.corrector.sha256 -eq (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Export-ScimValidationReport.ps1')).Hash.ToLowerInvariant()) 'Offline finalization records the correction implementation hash separately from original run provenance'
    $offlineOutputDirectory = Join-Path $fixtureDirectory 'offline-finalized'
    Write-ScimValidationReport $offline $offlineOutputDirectory -Zip
    $persistedOffline = Get-Content -LiteralPath (Join-Path $offlineOutputDirectory 'validation-run-details.json') -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($persistedOffline.offlineFinalization.sourceReportSha256 -eq $legacyHash -and
        $persistedOffline.galleryReadiness.exitCode -eq 1 -and
        (Get-Content -LiteralPath (Join-Path $offlineOutputDirectory 'validation-report.md') -Raw).Contains($legacyHash) -and
        (Test-Path -LiteralPath (Join-Path $offlineOutputDirectory 'validation-report.zip'))) 'The standard writer persists corrected JSON, Markdown and ZIP into a separate directory with original-report proof'
    $legacyFixture.evidenceFailures += @{ source = 'StillMissingComposeOutput'; reason = 'Successful data-producing action supplied no readable output evidence.'; required = $true }
    [IO.File]::WriteAllText($legacyPath, (ConvertTo-ScimCanonicalJson $legacyFixture), [Text.UTF8Encoding]::new($false))
    $partiallyOffline = Complete-ScimValidationReport -ReportPath $legacyPath
    Assert-Report ($partiallyOffline.completeness.requiredUnavailableCount -eq 1 -and $partiallyOffline.galleryReadiness.exitCode -eq 2) 'Offline correction leaves an unproven missing Compose output incomplete instead of waiving all Compose gaps'
    $legacyFixture.runtime.evidenceRequests.ContentPayload.failed = 1
    [IO.File]::WriteAllText($legacyPath, (ConvertTo-ScimCanonicalJson $legacyFixture), [Text.UTF8Encoding]::new($false))
    $offlineReason = $null
    try { [void](Complete-ScimValidationReport -ReportPath $legacyPath) } catch { $offlineReason = $_.Exception.Message }
    Assert-Report ($offlineReason -match 'zero failed downloads') 'Offline correction refuses to infer valid outputs when content downloads failed'
    $legacyFixture.runtime.evidenceRequests.ContentPayload.failed = 0; $legacyEntry.inputs = $null
    [IO.File]::WriteAllText($legacyPath, (ConvertTo-ScimCanonicalJson $legacyFixture), [Text.UTF8Encoding]::new($false))
    $offlineReason = $null
    try { [void](Complete-ScimValidationReport -ReportPath $legacyPath) } catch { $offlineReason = $_.Exception.Message }
    Assert-Report ($offlineReason -match 'sufficient recorded proof') 'Null Compose inputs or output length alone cannot be relabeled as collected empty strings'
    $legacyEntry.inputs = ''; $legacyEntry.securityExclusions = @(@{ source = 'outputs'; reason = 'Protected fixture.' })
    [IO.File]::WriteAllText($legacyPath, (ConvertTo-ScimCanonicalJson $legacyFixture), [Text.UTF8Encoding]::new($false))
    $offlineReason = $null
    try { [void](Complete-ScimValidationReport -ReportPath $legacyPath) } catch { $offlineReason = $_.Exception.Message }
    Assert-Report ($offlineReason -match 'sufficient recorded proof') 'Offline finalization cannot turn protected output bytes into collected evidence'
    $state.core = 'PASSED'; $state.oauth = 'SKIPPED'; $state.wif = 'SKIPPED'
    Assert-Report (-not (New-ScimValidationReport @reportArgs).galleryReadiness.ready) 'Selected auth skipped is not success'
    $state.oauth = 'PASSED'; $metadata.supportedAuthenticationMethods = @('Bearer')
    Assert-Report (-not (New-ScimValidationReport @reportArgs).galleryReadiness.ready) 'Bearer-only is not gallery-ready'
    $metadata.supportedAuthenticationMethods = @('OAuth2ClientCredentials')
    $state.deny = $true
    $incomplete = New-ScimValidationReport @reportArgs
    Assert-Report (-not $incomplete.completeness.complete -and $incomplete.galleryReadiness.exitCode -eq 2) 'Required evidence denied is incomplete and nonzero'
    Assert-Report (-not (ConvertTo-ScimCanonicalJson $incomplete).Contains('raw-live-denied')) 'ARM denial secrets never persisted'
    $state.deny = $false
    $state.omitCore = $true
    $missingCore = New-ScimValidationReport @reportArgs
    Assert-Report (-not $missingCore.completeness.complete -and -not $missingCore.galleryReadiness.ready) 'Missing expected core result is incomplete, not passing'
    $state.omitCore = $false; $state.omitAuth = $true
    Assert-Report ((New-ScimValidationReport @reportArgs).galleryReadiness.exitCode -eq 2) 'Missing authentication model summary is incomplete'
    $state.omitAuth = $false
    $unavailableArgs = $reportArgs.Clone()
    $unavailableArgs.Metadata = $metadata.Clone()
    $unavailableArgs.Metadata.preflight = @{ status = 'Passed'; startTime = '2026-01-01T00:00:00Z'; endTime = '2026-01-01T00:00:02Z' }
    $unavailableArgs.Request = { param($uri, $arm) throw 'ARM evidence could not be acquired.' }
    $unavailableRun = New-ScimValidationReport @unavailableArgs
    Assert-Report ($unavailableRun.fullRun.status -eq 'Unavailable' -and $unavailableRun.orchestratorRunId -eq 'exact-orchestrator') 'Requested execution with failed collection is Unavailable, never NotExecuted'
    Assert-Report ($null -eq $unavailableRun.fullRun.timing.startUtc -and $null -eq $unavailableRun.fullRun.timing.durationMilliseconds) 'Unavailable Azure run does not borrow passed-preflight timings'
    Assert-Report ($unavailableRun.fullRun.unavailableReason -and $unavailableRun.galleryReadiness.exitCode -eq 2) 'Unavailable requested execution has explicit reason and incomplete exit status'
    $state.omitCorrelation = $true
    $excluded = New-ScimValidationReport @reportArgs
    Assert-Report ($excluded.completeness.complete -and $excluded.completeness.securityExcludedCount -gt 0) 'Intentionally hidden child mappings without correlation do not falsely fail completeness'
    $metadata.workflowRuns = @(
        @{ workflowName = 'SCIMToken_Workflow'; runId = 'exact-auth-secure-first'; parentWorkflowName = 'UserTests_Workflow'; parentRunId = 'exact-UserTests_Workflow'; parentActionName = 'Call_Secure_Auth'; repetitionName = '0' },
        @{ workflowName = 'SCIMToken_Workflow'; runId = 'exact-auth-secure-second'; parentWorkflowName = 'UserTests_Workflow'; parentRunId = 'exact-UserTests_Workflow'; parentActionName = 'Call_Secure_Auth'; repetitionName = '1' }
    )
    $suppliedRuns = New-ScimValidationReport @reportArgs
    Assert-Report ($suppliedRuns.workflows.Count -eq 10 -and $suppliedRuns.completeness.complete) 'Caller-supplied exact protected child IDs collect all runs without correlation'
    Assert-Report (@($suppliedRuns.childRunAssociations | Where-Object attribution -match 'Caller-supplied').Count -eq 2) 'Caller-supplied associations remain distinctly attributed'
    $metadata.Remove('workflowRuns'); $state.omitCorrelation = $false
    $metadata.supportedAuthenticationMethods = @('WorkloadIdentityFederation')
    $metadata.scimAuthenticationMethod = 'WorkloadIdentityFederation'
    $state.wif = 'PASSED'; $state.oauth = 'NOT_APPLICABLE'
    $wifTransport = New-ScimValidationReport @reportArgs
    Assert-Report ($wifTransport.galleryReadiness.ready -and $wifTransport.authentication.scimRequestTransport.value -eq 'WorkloadIdentityFederation') 'WIF-only gallery alternative and direct transport require no OAuth credential evidence'
    $blockedArgs = $reportArgs.Clone(); $blockedArgs.OrchestratorRunId = ''
    $blocked = New-ScimValidationReport @blockedArgs
    Assert-Report ($null -eq $blocked.orchestratorRunId -and $blocked.fullRun.status -eq 'Blocked') 'Blocked export has no fake execution ID'
    Assert-Report ($blocked.galleryReadiness.exitCode -eq 2) 'Blocked export returns incomplete'
    $na = @(Get-ScimSemanticTests @{ testResults = @(@{ testName = 'Undeclared'; testResult = 'NOT_APPLICABLE'; applicable = $false; reason = 'Not declared' }) } @{} @())
    Assert-Report (-not $na[0].applicable -and $na[0].applicabilityReason -eq 'Not declared') 'Explicit non-applicability preserved'
    $noReason = @(Get-ScimSemanticTests @{ testResults = @(@{ testName = 'Undeclared'; testResult = 'NOT_APPLICABLE'; applicable = $false }) } @{} @())
    Assert-Report $noReason[0].applicable 'Non-applicable without reason cannot silently waive a test'
    $blockedMetadataPath = Join-Path $fixtureDirectory 'report-metadata.json'
    @{ supportedAuthenticationMethods = @('OAuth2ClientCredentials'); preflight = @{ status = 'Blocked'; reason = 'Fixture preflight was blocked.' } } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $blockedMetadataPath
    $cliOutput = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File (Join-Path $PSScriptRoot 'Export-ScimValidationReport.ps1') `
        -WorkDirectory $fixtureDirectory -AgentPath $agentPath -WorkflowDirectory $fixtureDirectory -MetadataPath $blockedMetadataPath 2>&1
    Assert-Report ($LASTEXITCODE -eq 2) 'CLI blocked execution exits 2 without Azure CLI'
    $blockedFile = Get-Content (Join-Path $fixtureDirectory 'validation-run-details.json') -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($null -eq $blockedFile.orchestratorRunId -and $blockedFile.fullRun.status -eq 'Blocked') 'CLI persists honest blocked report'
    $launcherPath = Join-Path $fixtureDirectory 'offline-executed-export.ps1'
    @'
param($Exporter, $WorkDirectory, $AgentPath, $WorkflowDirectory, $MetadataPath)
$ErrorActionPreference = 'Stop'
$global:failFirstArmRequest = $true
function az {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'version') { return 'fixture-cli' }
    if ($args[1] -eq 'show') { return '{"tenantId":"fixture-tenant","operatorIdentity":{"type":"user","name":"fixture"}}' }
    return '{"accessToken":"fixture-standalone-token","tenant":"fixture-tenant","expires_on":4102444800}'
}
function Invoke-RestMethod {
    [CmdletBinding()]
    param($Uri, $Headers, $Method, $MaximumRedirection, $TimeoutSec, $StatusCodeVariable)
    if ($StatusCodeVariable) { Set-Variable -Name $StatusCodeVariable -Value 200 -Scope 1 }
    if ($global:failFirstArmRequest) {
        $global:failFirstArmRequest = $false
        $errorObject = [System.Net.Http.HttpRequestException]::new('Fixture standalone HTTP401')
        $errorObject.Data['StatusCode'] = 401
        throw $errorObject
    }
    $p = @{status='Succeeded';startTime='2026-01-01T00:00:00Z';endTime='2026-01-01T00:00:01Z'}
    if ($Uri -match '/sites/[^/]+\?') { return @{identity=@{type='SystemAssigned';principalId='fixture'}} }
    if ($Uri -match '/actions\?') {
        if ($Uri -match '/Orchestrator_Workflow/') {
            $items = @()
            foreach ($child in @('Initialization_Workflow','UserTests_Workflow','GroupTests_Workflow','SCIMTests_Workflow')) {
                $cp=$p.Clone();$cp.outputs=@{headers=@{'x-ms-workflow-run-id'="cli-$child"}}
                $items+=@{name="Call_$child";properties=$cp}
            }
            $fp=$p.Clone()
            $fp.outputs=@{overallResult='PASSED';authenticationModelResult='PASSED';testResults=@(
                @{testName='Create_User_Test';testCategory='Mandatory';testResult='PASSED'},
                @{testName='OAuth2_Client_Credentials_Test';testCategory='Authentication';testResult='PASSED'},
                @{testName='Workload_Identity_Federation_Test';testCategory='Authentication';testResult='PASSED'}
            )}
            $items+=@{name='Final_TestResults';properties=$fp}
            return @{value=$items}
        }
        $p.outputs=@{result='PASSED'}
        return @{value=@(@{name='Fixture_Compose';properties=$p})}
    }
    if ($Uri -match '/runs/[^/]+\?') {
        $p.trigger=@{name='manual';status='Succeeded';startTime=$p.startTime;endTime=$p.endTime}
        return @{properties=$p}
    }
    throw 'Unexpected standalone fixture request.'
}
& $Exporter -WorkDirectory $WorkDirectory -AgentPath $AgentPath -WorkflowDirectory $WorkflowDirectory -MetadataPath $MetadataPath `
    -SubscriptionId fixture-subscription -ResourceGroupName fixture-group -LogicAppName fixture-app -TenantId fixture-tenant -OrchestratorRunId cli-root
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $launcherPath
    $executedOutputDirectory = Join-Path $fixtureDirectory 'standalone-executed'
    $executedCliOutput = & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $launcherPath `
        -Exporter (Join-Path $PSScriptRoot 'Export-ScimValidationReport.ps1') -WorkDirectory $executedOutputDirectory `
        -AgentPath $agentPath -WorkflowDirectory $fixtureDirectory -MetadataPath $blockedMetadataPath 2>&1
    Assert-Report ($LASTEXITCODE -eq 0) 'Standalone executed CLI resolves its private refreshing transport and completes using only offline fixtures'
    $standaloneReport = Get-Content (Join-Path $executedOutputDirectory 'validation-run-details.json') -Raw | ConvertFrom-Json -AsHashtable
    Assert-Report ($standaloneReport.runtime.arm401RetryCount -eq 1 -and $standaloneReport.completeness.complete) "Standalone CLI refreshes a simulated real HTTP401 and records no obsolete failure (retries=$($standaloneReport.runtime.arm401RetryCount), complete=$($standaloneReport.completeness.complete))"
    if ($EvidenceDirectory) {
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($EvidenceDirectory))
        $contract = @{
            purpose = 'Offline report-contract fixture only; not a live validation or gallery-readiness claim'
            assertionsPassed = $script:checks
            actualSourceVersion = @{
                value = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'VERSION') -Raw).Trim()
                sha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'VERSION') -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            historicalFixture = @{
                orchestratorRunId = $historicalReport.orchestratorRunId
                reportingSourceVersion = $historicalReport.provenance.sourceVersion
                observedRunVersion = $historicalReport.provenance.executedVersion
                historicalClaims = $historicalReport.historicalRun
                deployedVersionMatchesSource = $historicalReport.provenance.comparison.deployedVersionMatchesSource
            }
            currentFixture = @{
                orchestratorRunId = $currentRun.orchestratorRunId
                reportingSourceVersion = $currentRun.provenance.sourceVersion
                observedRunVersion = $currentRun.provenance.executedVersion
                recordedPolicy = $currentRun.authentication.recordedPolicy
                deployedVersionMatchesSource = $currentRun.provenance.comparison.deployedVersionMatchesSource
            }
            andPolicyFixture = @{
                recordedAggregate = $andFailure.authentication.recordedAggregateResult
                policyMismatch = $andFailure.authentication.aggregatePolicyMismatch
                methodResults = $andFailure.authentication.methodResults
                galleryReadiness = $andFailure.galleryReadiness
            }
            mixedBearerFixture = @{
                methodResults = $mixedPassing.authentication.methodResults
                bearerConnectivity = $mixedPassing.authentication.bearerConnectivity
            }
            interruptionFixture = @{
                savedStatus = $savedCheckpoint.collection.status
                savedReady = $savedCheckpoint.galleryReadiness.ready
                resumedPayloadCount = $checkpointResumed.resume.reusedPayloadCount
                resumedComplete = $checkpointResumed.completeness.complete
            }
        }
        $contractPath = Join-Path $EvidenceDirectory 'report-contract.json'
        [IO.File]::WriteAllText($contractPath, (ConvertTo-ScimCanonicalJson $contract) + "`n", [Text.UTF8Encoding]::new($false))
        $savedContract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json -AsHashtable
        Assert-Report ($savedContract.actualSourceVersion.sha256 -eq (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'VERSION')).Hash.ToLowerInvariant()) 'Optional contract artifact carries the actual source VERSION hash, separate from fixture source bytes'
        Assert-Report ($savedContract.historicalFixture.observedRunVersion.value -eq '11.0' -and $savedContract.currentFixture.observedRunVersion.value -eq '14.0' -and -not $savedContract.andPolicyFixture.galleryReadiness.ready) 'Persisted offline contract proves historical version separation and selected-method AND failure'
        $contract.assertionsPassed = $script:checks
        [IO.File]::WriteAllText($contractPath, (ConvertTo-ScimCanonicalJson $contract) + "`n", [Text.UTF8Encoding]::new($false))
    }
    Write-Host "PASS: $script:checks offline reporting assertions."
} finally {
    if (Test-Path -LiteralPath $fixtureDirectory) { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force }
}
