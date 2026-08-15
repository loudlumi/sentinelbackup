using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$ErrorActionPreference = 'Stop'
$correlationId = [guid]::NewGuid().ToString()

# --- Configuration from App Settings ---
$vaultName  = $env:KEY_VAULT_NAME
$secretName = $env:GITHUB_APP_PEM_SECRET   # value is the base64-encoded PEM
$issuer     = $env:GITHUB_APP_ID           # GitHub App ID (or Client ID) -> 'iss' claim

# ------------------------------------------------------------------ helpers ---
function Write-JsonResponse {
    param([HttpStatusCode]$Status, [hashtable]$Body)
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $Status
        Headers    = @{ 'Content-Type' = 'application/json' }
        Body       = ($Body | ConvertTo-Json -Depth 5 -Compress)
    })
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Retry only transient failures (timeouts, 429, 5xx) with exponential backoff.
function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$MaxAttempts = 3)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try { return & $Action }
        catch {
            $status    = $_.Exception.Response.StatusCode.value__   # $null for network/timeout
            $transient = ($null -eq $status) -or ($status -eq 429) -or ($status -ge 500)
            if (-not $transient -or $attempt -eq $MaxAttempts) { throw }
            Start-Sleep -Milliseconds ([int](200 * [math]::Pow(2, $attempt - 1)))
        }
    }
}

# ------------------------------------------------------------ config checks ---
$missing = @()
if (-not $vaultName)  { $missing += 'KEY_VAULT_NAME' }
if (-not $secretName) { $missing += 'GITHUB_APP_PEM_SECRET' }
if (-not $issuer)     { $missing += 'GITHUB_APP_ID' }
if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
    $missing += 'Managed identity (IDENTITY_ENDPOINT / IDENTITY_HEADER)'
}

if ($missing.Count -gt 0) {
    Write-Host "[$correlationId] Configuration error. Missing: $($missing -join ', ')"
    Write-JsonResponse ([HttpStatusCode]::InternalServerError) @{
        error         = 'Server configuration error.'
        correlationId = $correlationId
    }
    return
}

$rawB64  = $null
$pem     = $null
$kvToken = $null
try {
    # 1) Key Vault token via the Function App's managed identity
    $tokenUri = "$($env:IDENTITY_ENDPOINT)?resource=https://vault.azure.net&api-version=2019-08-01"
    $kvToken  = (Invoke-WithRetry {
        Invoke-RestMethod -Method Get -Uri $tokenUri -TimeoutSec 15 -Headers @{
            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
        }
    }).access_token

    # 2) Read the base64-encoded PEM from Key Vault
    $secretUri = "https://$vaultName.vault.azure.net/secrets/${secretName}?api-version=7.4"
    $rawB64 = (Invoke-WithRetry {
        Invoke-RestMethod -Method Get -Uri $secretUri -TimeoutSec 15 -Headers @{
            Authorization = "Bearer $kvToken"
        }
    }).value

    if ([string]::IsNullOrWhiteSpace($rawB64)) {
        throw "Secret '$secretName' was retrieved from '$vaultName' but is empty or disabled."
    }

    # 3) Decode base64 -> PEM (Trim guards against any stray leading/trailing whitespace)
    try {
        $pem = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($rawB64.Trim()))
    }
    catch {
        throw "Secret '$secretName' is not valid base64. Store the PEM base64-encoded with no newlines (Option 2)."
    }

    if ($pem -notmatch '-----BEGIN') {
        throw "Decoded secret '$secretName' does not look like a PEM (no BEGIN marker found)."
    }

    # 4) Build JWT header + payload
    $now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()   # Int64 — no cast needed
    $header  = @{ alg = 'RS256'; typ = 'JWT' } | ConvertTo-Json -Compress
    $payload = @{
        iat = $now - 60     # backdate 60s to tolerate clock skew
        exp = $now + 540    # 9 minutes (GitHub hard limit is 10)
        iss = $issuer
    } | ConvertTo-Json -Compress

    $signingText =
        "$(ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header)))." +
        "$(ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload)))"

    # 5) Sign header.payload with RS256 (RSA + SHA-256 + PKCS#1 v1.5)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportFromPem($pem.ToCharArray())
        $sigBytes = $rsa.SignData(
            [Text.Encoding]::UTF8.GetBytes($signingText),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    finally { $rsa.Dispose() }

    $jwt = "$signingText.$(ConvertTo-Base64Url $sigBytes)"

    Write-Host "[$correlationId] Minted GitHub App JWT for iss=$issuer (valid 540s)."
    Write-JsonResponse ([HttpStatusCode]::OK) @{
        token      = $jwt
        expires_at = [DateTimeOffset]::FromUnixTimeSeconds($now + 540).ToString('o')
    }
}
catch {
    # Log the real detail (Application Insights); return only a generic error + id.
    $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
    Write-Host "[$correlationId] Failed to mint token: $detail"
    Write-JsonResponse ([HttpStatusCode]::InternalServerError) @{
        error         = 'Failed to mint token.'
        correlationId = $correlationId
    }
}
finally {
    # Best-effort: shorten secret lifetime in memory (strings can't be reliably zeroed).
    Remove-Variable rawB64, pem, kvToken -ErrorAction SilentlyContinue
}
