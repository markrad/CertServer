Set-Item "env:REQUEST_PATH" -Value "/api/test"
Write-Host Exported CERTSERVER_HOST =((Get-Item -Path "Env:/CERTSERVER_HOST").Value)

function Autenticate {
    $userId = Read-Host -Prompt "Enter your username"
    $password = Read-Host -Prompt "Enter your password" -MaskInput

    $resp = Invoke-RestMethod -Method Post -Uri (Get-URIPrefix "login") -Body @{
        userId = $userId
        password = $password
    }
    if ($resp.success -ne $true) {
        Write-Host -ForegroundColor Red Authentication failed: $resp.Error
        Exit 4
    }
    else {
        Set-Item "env:CERTSERVER_TOKEN" -Value $resp.token
        Write-Host -ForegroundColor Green Authentication successful
    }
}
if ((Get-Item "Env:/AUTH_REQUIRED").Value -eq "1") {
    Write-Host Authentication Required
    Autenticate
}
function Get-ContentDispositionHeader {
    param (
        [Parameter(Mandatory)]
        [string]$UrlSuffix
    )
    $filename = ''
    try {
        $req = Invoke-WebRequest -Uri ((Get-URIPrefix) + $UriSuffix)
        $filename = $req.Headers.'Content-Disposition'.split(';')[1].Split('=')[1].Replace('"', '')
    }
    catch {
        Write-Host 'Request failed'
        Write-Host $_.ErrorDetails
        $filename = 'unknown.txt'
        $LASTEXITCODE = 4    
    }
    return $filename
}
function Get-URIPrefix {
    param (
        [string]$UrlSuffix
    )
    return (Get-Item -Path "Env:/CERTSERVER_HOST").Value + "/api/$UrlSuffix"
}
function Get-File_ {
    param (
        [Parameter(Mandatory)]
        [string]$UriSuffix
    )
    $filename = Get-ContentDispositionHeader $UriSuffix
    Invoke-WebRequest -Uri (Get-URIPrefix $UriSuffix) -OutFile ".\$filename"
    Write-Host ".\$filename written"
}
function New-SAS-Token {
    param (
        [Parameter(Mandatory)]
        [string]$ConnectionString
    )
    $endpoint = $null
    $keyName = $null
    $keyValue = $null
    if ($ConnectionString -match "HostName=([^;]+)") {
        $endpoint = $Matches.1
    }
    if ($ConnectionString -match "SharedAccessKeyName=([^;]+)") {
        $keyName = $Matches.1
    }
    if ($ConnectionString -match "SharedAccessKey=([^;]+)") {
        $keyValue = $Matches.1
    }
    if ($null -eq $endpoint -or $null -eq $keyName -or $null -eq $keyValue) {
        throw "Connection string is invalid"
    }
    $sasTTL = (Get-Date -Date (Get-Date).AddSeconds(3600).ToUniversalTime() -UFormat %s)
    $toEncrypt = "$endpoint`n$sasTTL"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Convert]::FromBase64String($keyValue)
    $sig = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($toEncrypt))
    $sig = [System.Web.HttpUtility]::UrlEncode([Convert]::ToBase64String($sig))
    $sas = "SharedAccessSignature sr=$endpoint&sig=$sig&se=$sasTTL&skn=iothubowner"
    return $sas
}
function Get-CertDetailsById {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $resp = [Internal]::GetCertDetailsById($CertificateId)
    if ($resp.Success -eq $false) {
        if ($resp.ReturnCode -eq 404) {
            Write-Host -ForegroundColor Yellow Certificate $CertificateId does not exist
        }
        else {
            Write-Host -ForegroundColor Red Error occured getting device: $resp.ReturnCode $resp.Error
        }
    }
    else {
        return $resp.Result
    }
}
function Get-CertKeyId {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $key = (Get-CertDetailsById $CertificateId).keyId
    if ($null -eq $key) {
        Write-Host -ForegroundColor Yellow Certificate $CertificateId does not have a key
    }
    else {
        return $key
    }
}
function Get-CertPem {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $uri = "getCertificatePem?id=$CertificateId"
    Get-File_ $uri
}
function Get-ChainAndKey {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $resp = [Internal]::GetCertDetailsById($CertificateId)
    if ($resp.Success -eq $false) {
        if ($resp.ReturnCode -eq 404) {
            Write-Host -ForegroundColor Yellow Certificate $CertificateId does not exist
        }
        else {
            Write-Host -ForegroundColor Red Error occured getting device: $resp.ReturnCode $resp.Error
        }
    }
    elseif ($null -eq $resp.Result.keyId) {
        Write-Host -ForegroundColor Yellow Certifcate $CertificateId does not have a key
    }
    else {
        Write-Host Getting chain $CertificateId
        Get-Chain $CertificateId
        Write-Host Getting key $resp.Result.keyId
        Get-KeyPem $resp.Result.keyId
    }
}
function Get-CertAndKey {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $resp = [Internal]::GetCertDetailsById($CertificateId)
    if ($resp.Success -eq $false) {
        if ($resp.ReturnCode -eq 404) {
            Write-Host -ForegroundColor Yellow Certificate $CertificateId does not exist
        }
        else {
            Write-Host -ForegroundColor Red Error occured getting device: $resp.ReturnCode $resp.Error
        }
    }
    elseif ($null -eq $resp.Result.keyId) {
        Write-Host -ForegroundColor Yellow Certifcate $CertificateId does not have a key
    }
    else {
        Write-Host Getting certificate $CertificateId
        Get-CertPem $CertificateId
        Write-Host Getting key $key
        Get-KeyPem $key
    }
}
function Get-Chain {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $uri = "chainDownload?id=$CertificateId"
    Get-File_ $uri
}
function Get-KeyPem {
    param (
        [Parameter(Mandatory)]
        [int]$KeyId
    )
    $uri = "getKeyPem?id=$KeyId"
    Get-File_ $uri
}
function Push-CertPem {
    param (
        [Parameter(Mandatory)]
        [string]$CertificateFilename
    )
    Invoke-RestMethod -Method Post -Uri (Get-URIPrefix "/api/uploadCert") -InFile $CertificateFilename -ContentType 'text/plain'
}
function Push-KeyPem {
    param (
        [Parameter(Mandatory)]
        [string]$KeyFilename
    )
    Invoke-RestMethod -Method Post -Uri (Get-URIPrefix "/api/uploadKey") -InFile $KeyFilename -ContentType 'text/plain'
}
function Get-CertDetailsByName {
    param (
        [Parameter(Mandatory)]
        [string]$CertificateCommonName
    )
    $resp = [Internal]::GetCertDetailsByName($CertificateCommonName)
    if ($resp.Success -eq $false) {
        if ($resp.ReturnCode -eq 404) {
            Write-Host -ForegroundColor Yellow Certificate $CertificateCommonName does not exist
        }
        elseif ($resp.ReturnCode -eq 400) {
            Write-Host -ForegroundColor Yellow Multiple Certificates with common name $CertificateCommonName exist
        }
        else {
            Write-Host -ForegroundColor Red Error occured getting device: $resp.ReturnCode $resp.Error
        }
    }
    else {
        return $resp.Result
    }
}
function New-LeafCertificate {
    param (
        [Parameter(Mandatory)]
        [string]$CertificateCommonName,
        [Parameter(Mandatory)]
        [int]$SignerId,
        [Parameter(Mandatory)]
        [int]$ValidDays
    )
    try {
        $resp = [Internal]::CreateLeafCertificate($CertificateCommonName, $SignerId, $ValidDays)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Error creating certificate: $resp.Error
        }
        else {
            return $resp.Result
        }
    }
    catch {
        Write-Host -ForegroundColor Red "An unexpected error occured: $_"
    }
}
function Remove-CertificateAndKey {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    try {
        $resp = [Internal]::GetCertDetailsById($CertificateId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Error acquiring certificate details $resp.Error
            Exit 4
        }
        if ($null -eq $resp.Result.keyId) {
            Write-Host -ForegroundColor Yellow The key for this certificate was not found
            Exit 1
        }
        $name = $resp.Result.name
        $resp = [Internal]::DeleteDeviceKey($resp.Result.keyId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Failed to delete key: $resp.error
            Exit 4
        }
        $resp = [Internal]::DeleteDeviceCertificate($CertificateId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Failed to delete certificate: $resp.error
            Exit 4
        }
        Write-Host Certificate and key for $name ($CertificateId) deleted
    }
    catch {
        Write-Host -ForegroundColor Red Unexpected error occured: $_
    }
}
function Remove-Certificate {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    try {
        $resp = [Internal]::GetCertDetailsById($CertificateId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Error acquiring certificate details $resp.Error
            Exit 4
        }
        $name = $resp.Result.name
        $resp = [Internal]::DeleteDeviceCertificate($CertificateId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Failed to delete certificate: $resp.error
            Exit 4
        }
        Write-Host Certificate for $name ($CertificateId) deleted
    }
    catch {
        Write-Host -ForegroundColor Red Unexpected error occured: $_
    }
}
function Remove-Key {
    param (
        [Parameter(Mandatory)]
        [int]$KeyId
    )
    try {
        $resp = [Internal]::DeleteDeviceKey($KeyId)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Failed to delete key: $resp.error
            Exit 4
        }
        Write-Host Key $KeyId deleted
    }
    catch {
        Write-Host -ForegroundColor Red Unexpected error occured: $_
    }
}
class ReturnCode {
    [Boolean] $Success
    [int] $ReturnCode
    [string] $Error
    [System.Object] $Result
    ReturnCode([hashtable]$Properties) { $this.Init($Properties) }
    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }
}
class Internal {
    static [ReturnCode] GetCertDetailsByName([string]$CertificateCommonName) {
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Uri (Get-URIPrefix "certdetails?name=$CertificateCommonName") -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] GetCertDetailsById([int]$CertificateId) {
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Uri (Get-URIPrefix "certdetails?id=$CertificateId") -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] CreateLeafCertificate([string]$CertificateCommonName, [int]$SignerId, [int]$ValidDays) {
        try {
            $ValidTo = (Get-Date).AddDays($ValidDays)
            $body = @{
                signer = $SignerId
                commonName = $CertificateCommonName
                validTo = $ValidTo.toString('MM/dd/yyyy')
            }
            $jsonBody = ConvertTo-Json $body
            $httprc = -1
            $headers = @{
                'Content-Type' = "application/json"
            }
            $resp = Invoke-RestMethod -Method POST -Uri (Get-URIPrefix "createleafcert") -Headers $headers -Body $jsonBody -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] DeleteDeviceCertificate([int] $CertificateId) {
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Method DELETE -Uri (Get-URIPrefix "deletecert?id=${CertificateId}") -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = $null
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] DeleteDeviceKey([int] $KeyId) {
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Method DELETE -Uri (Get-URIPrefix "deletekey?id=${KeyId}") -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = $null
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] GetServerStatistics([string]$SASToken, [string]$Url) {
        $headers = @{
            'Authorization' = $SASToken
        }
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Uri "https://$Url/statistics/service?api-version=2020-05-31-preview" -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] GetDevice([string]$SASToken, [string]$Url, [string]$DeviceId) {
        $headers = @{
            'Authorization' = $SASToken
        }
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Uri "https://$Url/devices/$($DeviceId)?api-version=2020-05-31-preview" -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] AddDevice([string]$SASToken, [string]$Url, [string]$DeviceId) {
        try {
            $headers = @{
                'Authorization' = $SASToken
                'Content-Type' = 'application/json'
            }
            $body = @{
                'deviceid' = $DeviceId
                'status' = 'enabled'
                'authentication' = @{
                    'type' = 'certificateAuthority'
                }
                'capabilities' = @{
                    'iotEdge' = $false
                }
            }
            $jsonBody = ConvertTo-Json $body
            $httprc = -1
            $resp = Invoke-RestMethod -Method PUT -Uri "https://$Url/devices/$($DeviceId)?api-version=2020-05-31-preview" -Headers $headers -Body $jsonBody -SkipHttpErrorCheck -StatusCodeVariable "httprc"
            if ($httprc -ne 200) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
    static [ReturnCode] RemoveDevice([string]$SASToken, [string]$Url, [string]$DeviceId, [string]$eTag) {
        $headers = @{
            'Authorization' = $SASToken
            'If-Match' = $eTag
        }
        try {
            $httprc = -1
            $resp = Invoke-RestMethod -Method DELETE -Uri "https://$Url/devices/$($DeviceId)?api-version=2020-05-31-preview" -Headers $headers -SkipHttpErrorCheck -StatusCodeVariable "httprc" -SkipHeaderValidation
            if ($httprc -ne 204) {
                return [ReturnCode]::new(
                    @{
                        Success    = $false
                        ReturnCode = $httprc
                        Error      = $resp
                        Result     = $null
                    }
                )
            }
            else {
                return [ReturnCode]::new(
                    @{
                        Success    = $true
                        ReturnCode = $httprc
                        Error      = ''
                        Result     = $resp
                    }
                )
            }
        }
        catch {
            return [ReturnCode]::new(
                @{
                    Success    = $false
                    ReturnCode = 1
                    Error      = $_
                    Result     = ''
                }
            )
        }
    }
}
function Get-Server-Statistics {
    param (
        [Parameter(Mandatory)]
        [string]$ConnectionString
    )
    try {
        Write-Host $ConnectionString
        $SASToken = New-SAS-Token $ConnectionString
    }
    catch {
        Write-Host -ForegroundColor Red Failed to generate SAS token: $_
    }
    try {
        if ($ConnectionString -match "HostName=([^;]+)") {
            $endpoint = $Matches.1
        }
        else {
            # This will probably never happen
            throw "Invalid connection string passed"
        }
        $resp = [Internal]::GetServerStatistics($SASToken, $endpoint)
        if ($resp.Success -eq $false) {
            Write-Host -ForegroundColor Red Error occured getting server statistics: $resp.Error
        }
        else {
            return $resp.Result
        }
    }
    catch {
        Write-Host "An unexpected error occured: $_"
    }
}
function Get-Device {
    param (
        [Parameter(Mandatory)]
        [string]$ConnectionString,
        [Parameter(Mandatory)]
        [string]$DeviceId
    )
    try {
        $SASToken = New-SAS-Token $ConnectionString
    }
    catch {
        Write-Host -ForegroundColor Red Failed to generate SAS token: $_
    }
    try {
        if ($ConnectionString -match "HostName=([^;]+)") {
            $endpoint = $Matches.1
        }
        else {
            # This will probably never happen
            throw "Invalid connection string passed"
        }
        $resp = [Internal]::GetDevice($SASToken, $endpoint, $DeviceId)
        if ($resp.Success -eq $false) {
            if ($resp.ReturnCode -eq 404) {
                Write-Host -ForegroundColor Yellow Device $DeviceId does not exist
            }
            else {
                Write-Host -ForegroundColor Red Error occured getting device: $resp.Error
            }
        }
        else {
            return $resp.Result
        }
    }
    catch {
        Write-Host "An unexpected error occured: $_"
    }
}

function Remove-Device {
    param (
        [Parameter(Mandatory)]
        [string]$ConnectionString,
        [Parameter(Mandatory)]
        [string]$DeviceId
    )

    try {
        $resp = [Internal]::GetCertDetailsByName($DeviceId)
        if ($resp.Success -eq $false) {
            if ($resp.ReturnCode -eq 404) {
                Write-Host -ForegroundColor Yellow Certificate $DeviceId does not exist - will delete device
            }
            elseif ($resp.ReturnCode -eq 400) {
                Write-Host -ForegroundColor Yellow Multiple Certificates with common name $DeviceId exist
            }
            else {
                Write-Host -ForegroundColor Red Error occured getting device: $resp.ReturnCode $resp.Error
            }
        }
        else {
            $keyId = $resp.Result.keyId
            $resp = [Internal]::DeleteDeviceCertificate($resp.Result.id)
            if ($resp.Success -ne $true) {
                Write-Host -ForegroundColor Red Failed to delete device certificate: $resp.Error
                return 4
            }
            else {
                Write-Host Certificate $DeviceId deleted
            }
            $resp = [Internal]::DeleteDeviceKey($keyId)
            if ($resp.Success -ne $true) {
                Write-Host -ForegroundColor Red Failed to delete device key: $resp.Error
                return 4
            }
            else {
                Write-Host Key deleted
            }
        }
        $SasToken = New-SAS-Token $ConnectionString
        $ConnectionString -match "HostName=([^;]+)"
        $Url = $Matches.1
        $resp = [Internal]::GetDevice($SasToken, $Url, $DeviceId)
        if ($resp.Success -ne $true) {
            Write-Host -ForegroundColor Red Error retrieving device from hub $resp.Error
            return 4
        }
        else {
            $resp = [Internal]::RemoveDevice($SasToken, $Url, $DeviceId, $resp.Result.etag)
            if ($resp.Success -eq $true) {
                Write-Host Device $DeviceId deleted
            }
            else {
                Write-Host -ForegroundColor Red Error deleting device from hub $resp.Error
                return 4
            }
        }
    }
    catch {
        Write-Host -ForegroundColor Red Unexpected error occured: $_
    }

    if ($deleteDevice) {
        
    }
}

function New-Device {
    param (
        [Parameter(Mandatory)]
        [string]$ConnectionString,
        [Parameter(Mandatory)]
        [int]$ParentCertificateId,
        [Parameter(Mandatory)]
        [string]$DeviceId
    )
    try {
        $createCert = $true
        $newCertId = $null
        $resp = [Internal]::GetCertDetailsByName($DeviceId)
        if ($resp.Success -eq $true) {
            if ($resp.Result.certType -ne 'leaf') {
                Write-Host -ForegroundColor Red Certificate is not a leaf certificate
                return 4
            }
            elseif ($null -eq $resp.Result.keyId) {
                Write-Host -ForegroundColor Red Certificate does not have a key available
                return 4
            }
            elseif ($resp.Result.signerId -ne $ParentCertificateId) {
                Write-Host -ForegroundColor Red Certificate is not signed by the specified parent
                return 4
            }
            Write-Host Certificate $DeviceId already exists and is suitable for X.509 authenticaton
            $newCertId = $resp.Result.id
            $createCert = $false
        }
        elseif ($resp.ReturnCode -ne 404) {
            Write-Host -ForegroundColor Red An error occured acquire $DeviceId details
            return 4
        }
        $resp = [Internal]::GetCertDetailsById($ParentCertificateId)
        if ($resp.ReturnCode -ne 200) {
            Write-Host -ForegroundColor Red Could not find the parent certificate with id $ParentCertificateId
            return 4
        }
        if ($resp.Response.certType -eq 'leaf') {
            Write-Host -ForegroundColor Red Specified parent certificate cannot sign a child
            return 4
        }
        $SasToken = New-SAS-Token $ConnectionString
        $ConnectionString -match "HostName=([^;]+)"
        $Url = $Matches.1
        $resp = [Internal]::GetDevice($SasToken, $Url, $DeviceId)
        if ($resp.Success) {
            Write-Host -ForegroundColor Red Device $DeviceId already exists
            return 4
        }
        elseif ($resp.ReturnCode -ne 404) {
            Write-Host -ForegroundColor Red Failed read device information $resp.Error
            return 4
        }

        $resp = [Internal]::AddDevice($SasToken, $Url, $DeviceId)
        if ($resp.Success -ne $true) {
            Write-Host -ForegroundColor Red Failed to create device $resp.Error
            return 4
        }
        Write-Host Device $DeviceId created
        if ($createCert -eq $true) {
            $resp = [Internal]::CreateLeafCertificate($DeviceId, $ParentCertificateId, 800)
            if ($resp.Success -eq $false) {
                Write-Host -ForegroundColor Red Failed to create certificate: $resp.Error
                return 4
            }
            Write-Host Certificate created
            $newCertId = $resp.Result.ids.certificateId
        }
        Write-Host Downloading new certificate chain and key
        Get-ChainAndKey $newCertId
    }
    catch {
        Write-Host -ForegroundColor Red Unexpected error occured: $_
    }
}
