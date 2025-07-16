<#
.SYNOPSIS
    Connects to the Apple School Manager (ASM) API by generating a valid JSON Web Token (JWT).

.DESCRIPTION
    This script handles the authentication process for the Apple School Manager API.
    It creates a signed JWT using your private key, Key ID, and Issuer ID from the Apple Developer portal.
    The script then uses this token to make a sample API call to retrieve a list of classes.

    You must replace the placeholder values in the "User Configuration" section with your own credentials.

.NOTES
    Author: Michael Dobbs & Gemini
    Version: 1.0
    Prerequisites: PowerShell 5.1 or higher (.NET Framework 4.7.2+ or .NET Core)

.REFERENCES
    https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-and-business-manager-api

#>

#--------------------------------------------------------------------------------
# User Configuration - REPLACE THESE VALUES
#--------------------------------------------------------------------------------

# Your private key ID from the Apple School/Business Manager portal (e.g., "d136aa66-0c3b-4bd4-9892-c20e8db024ab")
$keyId = "<<Your Key Here>"

# Your issuer ID from Apple School/Business Manager (a UUID, e.g., "BUSINESSAPI.9703f56c-10ce-4876-8f59-e78e5e23a152")
$issuerId = "<<Your clientId/issuerId Here>>"

$privateKeyPath = "<<Path to your PEM file>>" #ex: private-key.pem

# The base URL for the Apple School Manager API.
$audience = "https://account.apple.com/auth/oauth2/v2/token"
$apiBaseUrl = "https://api-school.apple.com"

#--------------------------------------------------------------------------------
# Helper Functions
#--------------------------------------------------------------------------------

# Function to convert a string or byte array to a Base64Url-encoded string.
# This format is required for JWTs.
function ConvertTo-Base64Url {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $InputObject
    )
    if ($InputObject -is [System.Byte[]]) { $bytes = $InputObject }
    else { $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputObject.ToString()) }
    return [System.Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

#--------------------------------------------------------------------------------
# Main Script Logic
#--------------------------------------------------------------------------------

# Initialize crypto objects to null for the finally block
$ecdsa = $null
$cngKey = $null

try {
    # Validate that the private key file exists
    if (-not (Test-Path -Path $privateKeyPath -PathType Leaf)) {
        throw "Private key file not found at: $privateKeyPath"
    }

    # --- 1. Construct the JWT Header ---
    $header = @{
        alg = "ES256" # Algorithm is always ES256
        kid = $keyId  # Your Key ID
    }
    $encodedHeader = ConvertTo-Base64Url -InputObject ($header | ConvertTo-Json -Compress)
    Write-Host "JWT Header: $($header | ConvertTo-Json)"
    Write-Host "Encoded Header: $encodedHeader"


    # --- 2. Construct the JWT Payload ---
    # Get the current time in Unix epoch seconds
    $issuedAtTime = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $expirationTime = $issuedAtTime + (60 * 60) # Set expiration time (e.g., 60 minutes from now).

    $payload = @{
        sub = $issuerId         # Subject is also your Issuer ID
        aud = $audience         # Audience must be the token endpoint
        iat = $issuedAtTime     # Issued At timestamp
        exp = $expirationTime   # Expiration timestamp
        jti = ([guid]::NewGuid()).ToString() #Apple documentation says to include a new GUID
        iss = $issuerId         # Your Issuer ID 
    }
    $encodedPayload = ConvertTo-Base64Url -InputObject ($payload | ConvertTo-Json -Compress)
    Write-Host "JWT Payload: $($payload | ConvertTo-Json)"
    Write-Host "Encoded Payload: $encodedPayload"


    # --- 3. Create the Signature (Cross-Platform) ---
    # The data to be signed is the encoded header and payload, joined by a period.
    $signingInput = "$encodedHeader.$encodedPayload"
    $signingInputBytes = [System.Text.Encoding]::ASCII.GetBytes($signingInput)

    # Read the raw private key from the .p8 file
    $privateKeyContent = Get-Content -Path $privateKeyPath -Raw
    $privateKeyB64 = $privateKeyContent -replace "-----BEGIN PRIVATE KEY-----`n" -replace "`n-----END PRIVATE KEY-----" -replace "`r" -replace "`n"
    $privateKeyBytes = [System.Convert]::FromBase64String($privateKeyB64)

    # Create an ECDsa object to perform the signing. The method depends on the PowerShell version.
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # PowerShell 6+ (.NET Core / .NET 5+) on Windows, macOS, or Linux
        Write-Host "Using .NET Core signing method for PowerShell 7+."
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportPkcs8PrivateKey($privateKeyBytes, [ref]$null) #Gemini said this should be [out]$null.  But that doesn't work in my environment.
    }
    else {
        # Windows PowerShell 5.1 (.NET Framework)
        Write-Host "Using Windows PowerShell 5.1 (CNG) signing method."
        $cngKey = [System.Security.Cryptography.CngKey]::Import($privateKeyBytes, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $ecdsa = New-Object System.Security.Cryptography.ECDsaCng($cngKey)
    }

    # Sign the data using the SHA256 algorithm
    $signatureBytes = $ecdsa.SignData($signingInputBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $encodedSignature = ConvertTo-Base64Url -InputObject $signatureBytes
    Write-Host "Signature created successfully."


    # --- 4. Assemble the Final JWT ---
    $jwt = "$signingInput.$encodedSignature"
    Write-Host "Successfully generated JWT." -ForegroundColor Green
    Write-Host $jwt


    # --- 5. Exchange JWT for a Bearer Token ---
    Write-Host "Requesting bearer token from Apple..."

    # This is a sample endpoint. You can change this to any valid ASM API endpoint.
    #$endpoint = "/v1/classes"
    $requestUri = $audience + "?grant_type=client_credentials&client_id=$issuerId&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$jwt&scope=school.api" #$apiBaseUrl$endpoint"

    # Create the authorization header
    $headers = @{
        "Host" = "account.apple.com"
        "Content-Type"  = "application/x-www-form-urlencoded"
    }

    # Make the web request
    $tokenResponse = Invoke-RestMethod -Uri $requestUri -Method POST -Headers $headers
    
    Write-Host "API Connection Successful!" -ForegroundColor Green
    #$bearerToken = $response
    #Write-Host "Response received:"
    #Write-Host $bearerToken
    #Write-Host "Response Converted:"
    # Display the response from the API
    #Write-Host $tokenResponse | ConvertTo-Json -Depth 5

    $accessToken = $tokenResponse.access_token
    if (-not $accessToken) {
        throw "Failed to acquire access token. Response: $($tokenResponse | ConvertTo-Json -Depth 5)"
    }
    Write-Host "Successfully acquired bearer token!" -ForegroundColor Green


    # --- 6. Query API Sample: Get Information about All Devices ---
    Write-Host "Querying for a list of organization devices..."
    $headers = @{ "Authorization" = "Bearer $accessToken" }

    $listDevicesUri = "$apiBaseUrl/v1/orgDevices?limit=100" # Maximum limit is 1000. Using a smaller limit for testing
    $deviceListResponse = Invoke-RestMethod -Uri $listDevicesUri -Method GET -Headers $headers

    Write-Host "API call successful. Found $($deviceListResponse.data.count) devices."
    if ($deviceListResponse.links.next) {
        Write-Host "Additional Pages Available..." -ForegroundColor Yellow
    } else {
        Write-Host "NO Additional Pages Available..."
    }
    # Write-Host ($deviceListResponse | ConvertTo-Json -Depth 5)


    # --- 7. Get Information About a Specific Device ---
    Write-Host "Querying for a single device by serial number..."
    $singleDeviceUri = "$apiBaseUrl/v1/orgDevices/KWX0NWNY2L" # Example serial number
    $singleDeviceResponse = Invoke-RestMethod -Uri $singleDeviceUri -Method GET -Headers $headers

    Write-Host "Single device response:"
    Write-Host ($singleDeviceResponse | ConvertTo-Json -Depth 5)

    # --- 8. Get Information About MDM Servers ---
    Write-Host "Querying for a list of MDM Servers..."
    $mdmServersUri = "$apiBaseUrl/v1/mdmServers"
    $mdmServersResponse = Invoke-RestMethod -Uri $mdmServersUri -Method GET -Headers $headers

    Write-Host "MDM Server response:"
    Write-Host ($mdmServersResponse | ConvertTo-Json -Depth 5)

    # --- 9. Get Information About Devices assigned to a particular MDM server ---
    Write-Host "Querying for a list of devices assigned to 1 MDM server..."
    $mdmServerDevicesUri = "$apiBaseUrl/v1/mdmServers/9DB0018E67B74BE4BF0D7DC311AAD4AE/relationships/devices"
    $mdmServerDevicesResponse = Invoke-RestMethod -Uri $mdmServerDevicesUri -Method GET -Headers $headers

    Write-Host "MDM Server response:"
    Write-Host ($mdmServerDevicesResponse | ConvertTo-Json -Depth 5)

}
catch {
    Write-Error "An error occurred: $_"
    if ($_.Exception.Response) {
        Write-Host $_.Exception.Response
        Write-Host ($_.Exception.Response | ConvertTo-Json -Depth 5)
    }
}
finally {
    # Clean up the cryptographic objects
    if ($null -ne $ecdsa) { $ecdsa.Dispose() }
    if ($null -ne $cngKey) { $cngKey.Dispose() }
}
