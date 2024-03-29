# CertServer

## Description
This is a simple website that is designed to help manage certificates and private keys. With that said please note **this is only intended for test scenarios with certificates and keys that are only used for testing. DO NOT use this for production certificates and keys. It is NOT SECURE.** If in doubt, then read the [LICENSE](./LICENSE).

## Justification
Typically, my job will require me to generate certificates for various purposes, self-signed certificate authorities, intermediates, and leaf certificates. Many of these are for X.509 authentication on test systems, as in, I don't care if you break into it because there is nothing useful.

The problem I would run into was tracking various certificates over a multitude of different machines for different purposes. Often I would end up using OpenSSL to regenerate them. I don't know about you, but I have to look up the OpenSSL arguments every time I need to do this.
## Usage
My solution to this is this simple web application. You can create a root certificate, from that create a chain of intermediate certificates, and finally a leaf certificate. Once they have all been created, you can download the leaf certificate's private key and the full certificate chain from the leaf up.

In my case, these certificates are typically used for X.509 authentication with an Azure Device Provisioning Service or an Azure IoT hub. These have been tested and work as expected. Also tested is generating a root and intermediate for use in an nested IoT Edge parent/child relationships. These also replace the Edge quick start certificates too.

You can also generate a root and a leaf and use it for protecting a website with TLS. The common name will need to match the fully qualified domain name of the server for this to work. Subject alternative names can also be added by IP or alternative DNS name.

You can also upload certificates and keys to it and it will determine if the new files have any relationship to the existing files such as one certificate being signed by another or a key being the pair to a certificate.

The webpage itself is fairly crude. I am not a web or even UI person. 
## Running the Server
Once you have cloned this GitHub repository, the main script takes just one optional argument which is the path to a configuration file. This is expected to be in yaml format and it will need to have an extension of yml, due to a limitation of the yaml parsing library I used. You start it thus:
`node output/index.js ./config.yml`  
There is a sample config file [here](./config_sample.yml). This are the settings that will be used if no config.yml is passed. It looks like this:
### The Default config File
```yaml
certServer:
  root: "./data"
  port: 4141
  certificate: null
  key: null
  subject:
    C: US
    ST: Washington
    L: Redmond
    O: None
    OU: None
``` 
### Config file options
- **certServer:** 
This is required  
  -  **root:** 
This specifies the root directory that the server will use to save certificates, private keys, and its database. Defaults to *./data*  
  - **port:** The port the webserver will listen on. Defaults to *4141*. 
  - **certificate:** When specified with a matching key, it will run the server in SSL mode.
  - **key:** Key for certificate above.
  - **subject:** If you want subject defaults, this is required  
    + **C:** Default for subject country  
    + **ST:** Default for subject state  
    + **L:** Default for subject location (city)  
    + **O:** Default for subject organization  
    + **OU:** Default for subject organizational unit  
## Running in a Docker Container
A [dockerfile](./docker/Dockerfile) is provided that will build an image to run the server in Linux Alpine and a [docker-compose](./docker/docker-compose.yml) file that show how you might run it using mounted volumes for the data and the config. It is recommended that you mount the directory that you specified as the root directory in the config and the directory that contains the config file itself.

The easier option is to pull the image from the ghcr repository. You can do this with latest or a specific version number (M.m.p such as 1.2.11):
```
docker pull ghcr.io/markrad/certserver:latest
```
Go to [the packages](https://github.com/markrad/CertServer/pkgs/container/certserver) page to see available versions.
Once you have the image you can either use the docker compose file mentioned above, or run it with:
```
docker run \
 -p 4141:4141 \
 -v /some/path/config.yml:/config/config.yml 
 -v /some/path/data:/path/specified/in/config
```
## Code Samples
Code samples to connect to an IoT hub or a DPS with self-signed or CA authentication are provided [here](./devicesamples/). Further documentation for these samples and setting up IoT Edge certificates can be found [here](./Examples.md).
 
## REST API

A REST API is also available since your host may not be capable of running a web browser. In most cases you can use the name of the certificate or key, but, since they are not guaranteed to be unique, you can also use the id displayed next to each certificate and key.

### Helper method
This method will (attempt) to return a script that you can utilize for acquiring certificates, certificate chains, and keys. If you are on Windows it will return a ps1 script and on Linux it will return a bash script. 
`POST http://server:4141/api/helper[?os=linux|windows|mac]`

The os parameter is optional. The server will attempt to determine the appropriate operating system from the user agent. If this is wrong or unsupported it can be overridden by specifying the required script.

This call will return a script which should be saved to your storage. For example on Linux or Mac:
```bash
curl http://server:4141/api/helper -o helper.sh
source helper.sh
# Get the certificate with id <id>
getcert <id>
# Get the key with id <id>
getkey <id>
# Get the certificate chain starting at id <id>
getchain <id>
```
or on Windows
```powershell
Invoke-WebRequest -Uri http://server:4141/api/helper -OutFile helper.ps1
. helper.ps1
# Get the certificate with id <id>
Get-CertPem <id>
# Get the key with id <id>
Get-KeyPem <id>
# Get the certificate chain starting at id <id>
Get-Chain <id>
```

### Create a new self-signed certificate authority (root CA)
`POST http://server:4141/api/createcacert`  
Post data:
```JSON
{
    "country": "optional country",
    "state": "optional state",
    "location": "optional location",
    "organization": "optional organization",
    "unit": "optional unit",
    "commonName": "required common name",
    "validFrom": "required date from in format yyyy/dd/dd",
    "validTo": "required date to in format yyyy/dd/dd"
}

```
Sample response:
```JSON
{
    "message": "Certificate/Key someName/someName_key added",
    "ids": {
      "certificateId": <id>,
      "keyId": <id>
    }
}
```
#### Examples
##### Curl
```bash
curl -X POST -H 'Content-type: application' --data '
{
  "country": "US",
  "state": "WA",
  "location": "anyCity",
  "organization": "myCompany",
  "unit": "three",
  "commonName": "test name",
  "validFrom": "2024\01\01"
  "validTo": "2028\01\01"
}'  http://myserver:4141/api/createcacert
```
### Create a new intermediate certificate
Intermediate certificates can be signed by either a root CA or another intermediate certificate.  
`POST http://server:4141/api/createintermediatecert`  
Post data:
```JSON
{
    "country": "optional country",
    "state": "optional state",
    "location": "optional location",
    "organization": "optional organization",
    "unit": "optional unit",
    "commonName": "required common name",
    "validFrom": "required date from in format yyyy/dd/dd",
    "validTo": "required date to in format yyyy/dd/dd",
    "signer": "id of certificate to sign this certificate",
    "password": "password for signer's key if required"
}

```
Sample response:
```JSON
{
    "message": "Certificate/Key intName/intName_key added",
    "ids": {
      "certificateId": <id>,
      "keyId": <id>
    }
}
```
#### Examples
##### Curl
```bash
curl -X POST -H 'Content-type: application' --data '
{
  "country": "US",
  "state": "WA",
  "location": "anyCity",
  "organization": "myCompany",
  "unit": "three",
  "commonName": "test name",
  "validFrom": "2024\01\01"
  "validTo": "2028\01\01",
  "signer": "15",
  "password": "secret-p@ssword"
}'  http://myserver:4141/api/createintermediatecert
```
### Create a new leaf certificate
Leaf certificates can be signed by either a root CA or intermediate certificate but they **cannot sign** other certificates.  
`POST http://server:4141/api/createleafcert`  
Post data:
```JSON
{
    "country": "optional country",
    "state": "optional state",
    "location": "optional location",
    "organization": "optional organization",
    "unit": "optional unit",
    "commonName": "required common name",
    "validFrom": "required date from in format yyyy/dd/dd",
    "validTo": "required date to in format yyyy/dd/dd",
    "signer": "id of certificate to sign this certificate",
    "password": "password for signer's key if required",
    "SANArray": [
      "DNS: a string for an alternative name such as localhost",
      "IP: an IP or IPv6 address in standard representation"
    ]
}

```
_Note, in the post data, the SANArray entries must begin with the string 'DNS: ' or 'IP: '. Anything else will be ignored._  
Sample response:
```JSON
{
    "message": "Certificate/Key leafName/leafName_key added",
    "ids": {
      "certificateId": <id>,
      "keyId": <id>
    }
}
```
#### Examples
##### Curl
```bash
curl -X POST -H 'Content-type: application' --data '
{
  "country": "US",
  "state": "WA",
  "location": "anyCity",
  "organization": "myCompany",
  "unit": "three",
  "commonName": "test name",
  "validFrom": "2024\01\01"
  "validTo": "2028\01\01",
  "signer": "15",
  "password": "secret-p@ssword",
  "SANArray": [
    "DNS:mysite.com",
    "IP:222.33.22.3"
  ]
}'  http://myserver:4141/api/createleafcert
```
### Get a list of certificates by type:  
`GET http://server:4141/api/certlist?type=root | intermediate | leaf | key`  
Sample response:  
```json
{
  "files": [
    {
      "name": "A_Root",
      "type": "root",
      "id": 1
    }
  ]
}
```
#### Examples
##### Curl
```bash
curl http://myserver:4141/api/certlist?type=leaf
```
##### PowerShell
```powershell
Invoke-WebRequest -Uri http://myserver:4141/api/certlist?type=leaf
```
### Download a certificate pem file:  
`GET http://server:4141/api/getcertificatepem?id=<certificate id>` or  
`GET http://server:4141/api/getcertificatepem?name=<certificate name>`  
Returns the pem file. If name is used and two certificates share the same common name it will fail with an error.
### Download the certificate's full chain file:
`GET http://server:4141/api/chaindownload?id=<certificate id>` or  
`GET http://server:4141/api/chaindownload?name=<certificate name>`  
Returns a pem file containing the full chain of certificates from the one selected up. This is in the correct order to pass as a full chain pem file. If name is used and two certificates share the same common name it will fail with an error.
### Upload a certificate pem file:  
`POST http://server:4141/api/uploadcert`  
Uploads an existing certificate to the server. The pem string is placed in the post data. The POST must follow the following conventions:  
  + The pem content is in standard 64 byte lines. Hint: use --data-binary @filename when using curl
  + The Content-Type header must be set to text/plain. In curl -H "Content-Type: text/plain"  
Sample response:
```json
{
  "message":"Certificate Baltimore_CyberTrust_Root of type root added",
    "ids": {
      "certificateId": <id>
    }
}
```
##### Curl
```
curl -X POST -H "Content-Type: text/plain" --data-binary @./mycert.pem http://myserver:4141/api/uploadcert 
```
##### PowerShell
```powershell
$body = [System.IO.File]::ReadAllText('.\mycert.pem')
Invoke-WebRequest -Uri http://myserver:4141/api/uploadcert `
  -ContentType 'text/plain' `
  -Method POST `
  -Body $body
```
### Get a certificate's details
Returns the pertinent details of a specific certificate including the tags.  
`GET http://server:4141/api/certDetails?id=<certificate id>` or  
`GET http://server:4141/api/certDetails?name=<certificate name>`  
Sample response:
```json
{
  "id": 128,
  "certType": "root",
  "name": "test name",
  "issuer": {
    "C": "US",
    "ST": "WA",
    "L": "anyCity",
    "O": "myCompany",
    "OU": "three",
    "CN": "test name"
  },
  "subject": {
    "C": "US",
    "ST": "WA",
    "L": "anyCity",
    "O": "myCompany",
    "OU": "three",
    "CN": "test name"
  },
  "validFrom": "2024-01-01T08:00:00.000Z",
  "validTo": "2028-01-01T08:00:00.000Z",
  "serialNumber": "18:2b:df:a7:97:d7:10:d5:f0:e6:b9:92:b9:1d:40:63:1a:81:a0:65",
  "signer": "test name",
  "signerId": 128,
  "keyId": 121,
  "fingerprint": "1F:C8:6B:58:A8:5E:EB:57:56:E2:F3:14:09:C0:52:D4:84:FF:11:00",
  "fingerprint256": "B6:88:4E:B2:81:44:DE:0D:89:CE:AE:47:E1:01:CE:E5:2B:16:A3:E5:89:63:17:CE:31:6C:65:C6:E7:38:8C:CD",
  "signed": [
    127,
    128
  ],
  "tags": [
    "tag 2",
    "tag 3",
    "tag 1"
  ]
}
```
### Update a certificate's tags
__Replace__ the tags associated with the certificate. Note the tags passed will replace all of the tags currently associated with the certificate.  
`POST http://server:4141/api/updateCertTag?id=<certificate id>` or  
`POST http://server:4141/api/updateCertTag?name=<certificate name>`  
Post data:
```json
{
  "tags": [ "tag-a", "tag-b" ]
}
```
Sample response:
```json
{
  "message": "Certificate tags updated"
}
```
### Delete a certificate:  
`DELETE http://server:4141/api/deleteCert?id=<certificate id>` or  
`DELETE http://server:4141/api/deleteCert?name=<certificate name>`  
Deletes the certificate from the server. If name is used and two certificates share the same common name it will fail with an error.  
Sample response:
```json
{
  "message": "Certificate deleted"
}
```
#### Examples
##### Curl
```bash
curl -X DELETE http://myserver:4141/api/deleteCert?id=33
```
### Get a list of keys:  
`GET http://server:4141/api/keylist`  
Sample response:  
```json
{
  "files": [
    {
      "name": "A_Key",
      "type": "key",
      "id": 1
    }
  ]
}
```
### Download a key pem file:  
`GET http://server:4141/api/getkeypem?id=<key id>` or  
`GET http://server:4141/api/getkeypem?name=<key name>`  
Returns the pem file. If name is used and two keys share the same common name it will fail with an error.
### Upload a key pem file:  
`POST http://server:4141/api/uploadkey`  
Uploads an existing key to the server. The pem data is placed in the post data. The POST must follow the following conventions:  
  + The pem content is in standard 64 byte lines. Hint: use --data-binary @filename when using curl
  + The Content-Type header must be set to text/plain. In curl -H "Content-Type: text/plain"  
Sample response:
```json
{
    "message": "Key intName_key added",
    "ids": {
      "keyId": <id>
    }
}
```
#### Examples
##### Curl
```bash
curl -X POST -H "Content-Type: text/plain" --data-binary @./mykey.pem http://myserver:4141/api/uploadkey 
```
##### PowerShell
```powershell
$body = [System.IO.File]::ReadAllText('.\mykey.pem')
Invoke-WebRequest -Uri http://myserver:4141/api/uploadkey `
  -ContentType 'text/plain' `
  -Method POST `
  -Body $body
```
### Delete a key:  
`DELETE http://server:4141/api/deletekey?id=<key id>` or  
`DELETE http://server:4141/api/deletekey?name=<key name>`  
Deletes the key from the server. If name is used and two certificates share the same common name it will fail with an error.
