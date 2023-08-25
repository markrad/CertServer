# Usage Examples

Examples of what certificates are needed by various Azure IoT and DPS, and how to generate them.
## Non-Azure Scenarios
### Top-level Certificate
Generate an overall self-signed certificate that is the ultimate parent of all other certificates. This is intended to represent the trusted root certificate used to sign the certificate you would purchase from a certificate vendor. One of these is adequate, and it should be trusted by your devices.
### Webserver TLS Certificate
Sign a leaf certificate with the top-level certificate and use that certificate and its private key to add TLS to a resource. This application has the option to run in TLS mode. See the configuration settings. This certificate pair could also be used to docker registry container for example.
## Azure IoT and DPS Scenarios
All of the certificates generated for IoT and DPS scenarios are chained from a single certificate. That certificate is signed by the top-level certificate described above. For the remainder of the documentation, this certificate will be referred to as **_CertTestRoot_**.
### CertTestRoot
Create a new intermediate certificate from the top-level certificate. This will the root of all the other IoT and DPS certificates.
### DPS
X.509 authentication can be specified for a group enrollment. A certificate will need to be uploaded to the DPS to serve as the parent for all of the device certificates. There are two ways to set up a group enrollment. Either sign the device certificates with the uploaded certificate or generate an intermediate certificate and sign the devices with that. If you wish to use both mechanisms, then you will need to upload a separate certificate for each, a direct certificate and an indirect certificate. If you don't do this, all the devices will be assigned to the direct enrollment group.  
***Note: device identities must be lower case.***
#### Direct Certificate
Sign a new intermediate CA certificate with CertTestRoot. Upload this to the DPS. Create an enrollment group and pick an attestation mechanism of _X.509 certificates uploaded to this Device Provisioning Service instance_. Select the certificate you uploaded. With the certificate you have uploaded, sign a new leaf certificate that has the CN of the device identity you need. Put leaf certificate full chain and the private key on the device and use them to authenticate with DPS.
#### Indirect Certificate
Sign a new intermediate CA certificate with CertTestRoot. Upload this to the DPS. With that new certificate, sign another CA certificate. Create an enrollment group and pick an attestation mechanism of _C.509 intermediate certificates_. DPS will ask you to provide an intermediate for this. Upload the second certificate. Use the second certificate to sign a new leaf certificate that has the CN of the device identity you need. Put leaf certificate full chain and the private key on the device and use them to authenticate with DPS.
#### DPS and Edge devices
The process of creating the certificates is identical for both direct and indirect. The only difference is that you must check the _Enable IoT Edge on provisioned devices_ box. Once you have generated the device leaf certificate pair, add the certificate full chain and the key to the `/etc/aziot/config.toml` file as follows:
```toml
[provisioning]
source = "manual"
iothub_hostname = "<fully qualified name of the IoT hub>"
device_id = "<device id - must match the CN in the certificate>"
[provisioning_authentication]
method = "X509"
identity_pk = "file://</path/to/private_key>"               # Private key
identity_cert = "file://</path/to/certificate_full_chain>"  # Leaf full chain
```
Run `sudo iotedge config apply` after saving that file.
### Certificate Hierarchy for Above
```
Root
└──	CertTestRoot (CA)
    ├── DPS direct certificate (CA)
    │   └──	Device certificate (leaf)
    └── DPS indirect certificate (CA)
        └──	Intermediate certificate (CA)
            └──	Device certificate (leaf)
``````