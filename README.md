# CertServer

## Description
This is a simple website that is designed to help manage certificates and private keys. With that said please note **this is only intended for test scenarios with certificates and keys that are only used for testing. DO NOT use this for production certificates and keys. It is NOT SECURE.** If in doubt, then read the [LICENSE](./LICENSE).

## Justification
Typically, my job will require me to generate certificates for various purposes, self-signed certificate authorities, intermediates, and leaf certificates. Many of these are for X.509 authentication on test systems, as in, I don't care if you break into it because there is nothing useful.

The problem I would run into was tracking where these various certificates over a multitude of different desktops and, often I would end up using OpenSSL to regenerate them. I don't know about you, but I have to look up the OpenSSL arguments every time I need to do this.
## Usage
My solution to this was this simple website. One can create a root certifcate, from that create a chain of intermediate certifcates, and finally a leaf certificate. Once they have all been created, one can download the leaf certificate's private key and the full certificate chain from the leaf up.

In my case, these certificates are typically used for X.509 authentication with Azure Device Provisioning Service and Azure IoT hub. These have been tested and work as expected. Also tested is generating a root and intermediate for use in an nested IoT Edge parent/child relationship. These also replace the Edge quick start certificates too.

You can also generate a root and a leaf and use it for protecting a website with TLS. The common name will need to match the fully qualified domain name of the server for this to work. Subject alternative names can also be added by IP or alternative DNS name.

You can also upload certificates and keys to it and it will determine if the new files have any relationship to the existing files such as one certificate being signed by another or a key being the pair to a certificate.

The webpage itself is fairly crude. I am not a web or even UI person. 
## Running the Server
Once you have cloned this GitHub repository, the main script takes just one optional argument which is the path to a configuration file. This is expected to be in yaml format and it will need to have an extension of yml, due to a limitation of the yaml parsing library I used. You start it thus:
`node output/index.js ./config.yml`  
There is a sample config file [here](./config_sample.yml). This is the setting that will be used if no config.yml is passed. It looks like this:
### The Default config File
```yaml
certServer:
  root: "./data"
  port: 4141
  subject:
    C: USA,
    ST: Washington,
    L: Redmond,
    O: None,
    OU: None
``` 
### Config file options
**certServer:** 
This is required  
>**root:** 
This specifies the root directory that the server will use to save certificates, private keys, and its database. Defaults to *./root*  
>**port:** The port the webserver will listen on. Defaults to *4141*.  
>**subject:** If you want subject defaults, this is required  
>>>**C:** Default for subject country  
>>>**ST:** Default for subject state  
>>>**L:** Default for subject location (city)  
>>>**O:** Default for subject organization  
>>>**OU:** Default for subject organizational unit  
## Running in a Docker Container
A [dockerfile](./docker/dockerfile) is provided that will build an image to run the server in Linux Alpine and a [docker-compose](./docker/docker-compose.yml) file that show how you might run it using mounted volumes for the data and the config. It is recommended that you mount the directory that you specified as the root directory in the config and the directory that contains the config file itself.

The easier option is to pull the image from the ghcr repository. You can do this with:
```
docker pull ghcr.io/markrad/certserver:1.2.3
```
Currently all images will have a verion number. There is no latest. Once you have the image you can either use the docker compose file mentioned above, or run it with:
```
docker run \
 -p 4141:4141 \
 -v /some/path/config.yml:/config/config.yml 
 -v /some/path/data:/config/specified/config.yml
```
## REST API

A REST API is also available since your host may not be capable of running a web browser. In most cases you can use the name of the certificate or key, but, since they are not guaranteed to be unique, you can also use the id displayed next to each certificate and key.

### Create a new self-signed certificate authority (root CA)
POST `http://server:4141/api/createcacert`  
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
    "types": "root;key"
}
```
### Create a new intermediate certificate
Intermediate certificates can be signed by either a root CA or another intermedidate certificate.  
POST `http://server:4141/api/createintermediatecert`  
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
    "signer": "id of certificate to sign this certificate"
}

```
Sample response:
```JSON
{
    "message": "Certificate/Key intName/intName_key added",
    "types": "intermediate;key"
}
```
### Create a new leaf certificate
Leaf certificates can be signed by either a root CA or intermedidate certificate but they **cannot sign** other certificates.  
POST `http://server:4141/api/createleafcert`  
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
    "SANArray": [
      "DNS: a string for an alternative name such as localhost",
      "IP: an IP or IPv6 address in standard representation"
    ]
}

```
Note in the post data, the SANArray entries must begin with the string 'DNS: ' or 'IP: '.
Sample response:
```JSON
{
    "message": "Certificate/Key leafName/leafName_key added",
    "types": "leaf;key"
}
```
### Get a list of certificates by type:  
GET `http://server:4141/api/certlist?type=root | intermediate | leaf | key`  
Sample output:  
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
### Download a certificate pem file:  
GET `http://server:4141/api/getcertificatepem/id=<certificate id>` or  
GET `http://server:4141/api/getcertificatepem/name=<certificate name>`  
Returns the pem file. If name is used and two certicates share the same common name it will fail with an error.
### Download the certificate's full chain file:
GET `http://server:4141/api/chaindownload/id=<certificate id>` or  
GET `http://server:4141/api/chaindownload/name=<certificate name>`  
Returns a pem file containing the full chain of certificates from the one selected up. This is in the correct order to pass as a full chain pem file. If name is used and two certicates share the same common name it will fail with an error.
### Upload a certificate pem file:  
POST `http://server:4141/api/uploadcert`  
Uploads an existing certificate to the server. The pem data is placed in the post data. The POST must follow the following conventions:  
  + The pem content is in standard 64 byte lines. Hint: use --data-binary @filename when using curl
  + The Content-Type header must be set to text/plain. In curl -H "Content-Type: text/plain"  
Sample response:
```json
{
  "message":"Certificate Baltimore_CyberTrust_Root added",
  "type":"root"
}
```
### Delete a certificate:  
DELETE `http://server:4141/api/deleteCert/id=<certificate id>` or  
DELETE `http://server:4141/api/deleteCert/name=<certificate name>`  
Deletes the certificate from the server. If name is used and two certicates share the same common name it will fail with an error.
### Get a list of keys:  
GET `http://server:4141/api/keylist`  
Sample output:  
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
GET `http://server:4141/api/getkeypem/id=<key id>` or  
GET `http://server:4141/api/getkeypem/name=<key name>`  
Returns the pem file. If name is used and two keys share the same common name it will fail with an error.
### Upload a certificate pem file:  
POST `http://server:4141/api/uploadkey`  
Uploads an existing key to the server. The pem data is placed in the post data. The POST must follow the following conventions:  
  + The pem content is in standard 64 byte lines. Hint: use --data-binary @filename when using curl
  + The Content-Type header must be set to text/plain. In curl -H "Content-Type: text/plain"  
Sample response:
```json
{
    "message": "Key intName_key added",
    "type": "key;intermediate"
}
```
### Delete a key:  
DELETE `http://server:4141/api/deletekey/id=<key id>` or  
DELETE `http://server:4141/api/deletekey/name=<key name>`  
Deletes the key from the server. If name is used and two certicates share the same common name it will fail with an error.
