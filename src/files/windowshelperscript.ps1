Write-Host Exported CERTSERVER_HOST =((Get-Item -Path "Env:/CERTSERVER_HOST").Value)

function Get-Filename_ {
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
    $filename = Get-Filename_ $UriSuffix
    Invoke-WebRequest -Uri (Get-URIPrefix $UriSuffix) -OutFile ".\\$filename"
    Write-Host ".\\$filename written"
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
    return Invoke-RestMethod -Uri (Get-URIPrefix "certdetails?id=$CertificateId")
}
function Get-CertKeyId {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $key = (Get-CertDetailsById $CertificateId).keyId
    return $key
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
    $key = Get-CertKeyId $CertificateId

    if (!$key) {
        Write-Host Certificate does not have a key available
    }
    else {
        Write-Host Getting chain $CertificateId
        Get-Chain $CertificateId
        Write-Host Getting key $key
        Get-KeyPem $key
    }
}
function Get-CertAndKey {
    param (
        [Parameter(Mandatory)]
        [int]$CertificateId
    )
    $key = Get-CertKeyId $CertificateId

    if (!$key) {
        Write-Host Certificate does not have a key available
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
    Invoke-RestMethod -Uri (Get-URIPrefix "certdetails?name=$CertificateCommonName")
}
function Set-Exit-Code {
    param (
        [Parameter(Mandatory)]
        [int]$ExitCode
    )
    $LASTEXITCODE = $ExitCode
    return
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
        if ($ConnectionString -match "HostName=([^;]+)") {
            $endpoint = $Matches.1
        }
        else {
            # This will probably never happen
            throw "Invalid connection string passed"
        }
        $headers = @{
            'Authorization' = $SASToken
        }
        $resp = Invoke-RestMethod -Uri "https://$endpoint/devices/$($DeviceId)?api-version=2020-05-31-preview" -Headers $headers
        return $resp
    }
    catch {
        if ($_.ErrorDetails) {
            if ($_.ErrorDetails.Message -match "ErrorCode:([^;]+)") {
                $msg = $Matches.1
                if ($msg -eq "DeviceNotFound") {
                    Write-Host "$DeviceId was not found"
                    return Set-Exit-Code 1
                }
                else {
                    Write-Host "Error $msg"
                    return Set-Exit-Code 2
                }
            }
            else {
                Write-Host $_.ErrorDetails.Message
                return  Set-Exit-Code 3
            }
        }
        else {
            Write-Host "An unexpected error occured: $_"
            return  Set-Exit-Code 4
        }
    }
}