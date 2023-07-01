# CertServer

## Description
This is a simple website that is designed to help manage certificates and private keys. With that said please note **this is only intended for test scenarios with certificates and keys that are only used for testing. DO NOT use this for production certificates and keys. It is NOT SECURE.** If in doubt, then read the [LICENSE](./LICENSE).

## Justification
Typically, my job will require me to generate certificates for various purpose, self-signed certificate authorities, intermediates, and leaf certificates. Many of these are for X.509 authentication on test systems, as in, I don't care if you break into it because there is nothing useful.

The problem I would run into was tracking where these various certificates were over a multitude of different desktops and, often I would end up using OpenSSL to regenerate them. I don't know about you, but I have to look up the OpenSSL arguments every time I need to do this.
## Usage
My solution to this was this simple website. One can create a root certifcate, from that create a chain of intermediate certifcates, and finally a leaf certificate. Once they have all been created, one can download the leaf certificate's private key and the full certificate chain from the leaf up.

In my case, these certificates are typically used for X.509 authentication with Azure Device Provisioning Service and Azure IoT hub. These have been tested and work as expected. Also tested is generating a root and intermediate for use in an nested IoT Edge parent child relationship and for using your own certificates rather than quck start certificates.

You can also generate a root and a leaf and use it for protecting a website with TLS. The common name will need to match the fully qualified domain name of the server for this to work. Currently you cannot use this to add subject alternate names though it does add one for the common name.

You can also upload certificates and keys to it and it will determine if the new files have any relationship to the existing files such as one certificate being signed by another or a key being the pair to a certificate.

The webpage itself is fairly crude. I am not a web or even UI person. 
## REST API

The server does offer a limited REST API as follows:

- To download a certificate simply use   
`https://<yourserver>:<yourport>/certificates/<certificate_name>.pem`
- Similarly to download a key use  
`https://<yourserver>:<yourport>/keys/<key_name>.pem`
- To download a chain, use GET  
`http://<yourserver>:<yourport>/api/chaindownload?name=<lowestcertname>`
- To upload a certificate use POST  
`http://<yourserver>:<yourport>/api/uploadCert`  
where the POST data contains the pem contents and the Content-Type is text/plain. Make sure you are not removing the newline characters. For example, with curl use --data-binary @/path/to/certificate/name.
- To upload a key use POST  
`http://<yourserver>:<yourport>/api/uploadCert`  
The same rules apply as uploading a certificate above
- To delete a certificate use DELETE  
`http://<yourserver>:<yourport>/api/deleteCert?name=<certname>` or  
`http://<yourserver>:<yourport>/api/deleteCert?serialNumber-<serialNumber>` 
- To delete a key use DELETE  
`http://<yourserver>:<yourport>/api/deleteKey?name=<keyname>`

## Running the Server
Configuration is done by passing a yaml file as the only argument to the script as in  
`node output/index.js ./config.yml`  
for example. You can find a sample config file [here](./config_sample.yml). This file, due to a restriction in the library I used, must have a file extension of yml. If a configuration file is not passed then it will default to the values in the sample.  
And that is pretty much it except for 
## Running it in a Docker Container
Also provided are a [dockerfile](./docker/dockerfile) that will build an image to run the server in Linux Alpine and a [docker-compose](./docker/docker-compose.yml) file that show how you might run it using mounted volumes for the data and the config.