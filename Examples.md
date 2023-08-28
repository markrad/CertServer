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
source = "dps"
global_endpoint = "https://global.azure-devices-provisioning.net/"
id_scope = "<your DPS scope id>"
[provisioning_attestation]
method = "x509"
registration_id = "<your device identity>"
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
```
### IoT Hub
#### X.509 CA Authentication
Sign a new intermediate CA certificate with CertTestRoot. Upload the certificate to the IoT hub. Use this certificate to sign a leaf certificate with a CN that equals the device identity. Use the full chain leaf certificate and its private key for X.509 authentication with the IoT hub.
#### Self-signed Certificate Authentication
Sign a leaf certificate with literally any CA. It can also be self-signed but this tool does not have that facility. Copy the fingerprint and provide it when creating the device. Again, this certificate's CN must match the device identity.
#### Self-signed Certificate Authentication with Edge
Follow the instructions above to create the certificate and add the device with the fingerprint. Set up the config file as follows:
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
Edge devices do not support X.509 CA authentication.
### Other Edge Miscellany
Edge uses certificates in two other places. One set, if not provided, will be generated. These are known as quick start certificates. Generating you own has two advantages. First it will stop the warning being generated in the `iotedge check` output, and it will enable a nested Edge scenario.

To set this up you will first need to sign a new CA intermediate certificate with CertTestRoot. Take that certificate's full chain and its private key and add it to the config.toml as 
```toml
[edge_ca]
cert = "file://</path/to/certificate_full_chain>"  # Intermediate full chain
pk = "file://</path/to/private_key>"               # Private key
```
This certificate will be used to sign a certificate with a CN that matches the hostname specified in the config. It is important that the hostname is resolvable by DNS in transparent gateway scenarios or the TLS negotiation will fail. 

A downstream device that receives this certificate must trust the root of the chain which, in this example, will be the signer of CertTestRoot that was created at the very beginning. The Microsoft IoT device SDKs provide various mechanisms to accomplish that though simply adding it to the trusted root store will often work.

In a nested Edge scenario, the edgeHub and edgeAgent containers will also need to trust that certificate. To do this, you need to add the root certificate to the Edge trust bundle. This file can contain multiple certificates concatenated together as required. Either create this file with the root in it or append the root to the end of an existing file. In the config.toml you specify:
```toml
trust_bundle_cert = "file//</your/trust/bundle>"
```
### Certificate Hierarchy for Above
```
Root
└──	CertTestRoot (CA)
    └── IoT Hub Root (CA)
         ├─	Device X.509 (leaf)
         ├─	Device self-signed (leaf)
         └─ Intermediate certificate (CA) for Edge CA
```