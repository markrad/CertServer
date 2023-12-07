# Usage Examples

Examples of what certificates are needed by various Azure IoT and DPS, and how to generate them.
## Non-Azure Scenarios
### Top-level Certificate
Generate an overall self-signed certificate that is the ultimate parent of all other certificates. This is intended to represent the trusted root certificate used to sign the certificate you would purchase from a certificate vendor. One of these is adequate, and it should be trusted by your devices.
### Webserver TLS Certificate
Sign a leaf certificate with the top-level certificate and use that certificate and its private key to add TLS to a resource. This application has the option to run in TLS mode. See the configuration settings. This certificate pair could also be used to docker registry container for example. Note that the certificate's common name (CN) must be identical to the host name. For example, if you host a web server on a machine that is reached by a DNS name of *mywebserver.lan* then that will need to be the common name. You can also add alternative names such as *localhost* or an IP address.
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
#### Certificate Hierarchy for Above
```
Root
└──	CertTestRoot (CA)
    └── IoT Hub Root (CA)
         ├─	Device X.509 (leaf) - device only since Edge does not support X.509 CA authentication
         └─ Device self-signed (leaf) - device or Edge
```
### Nested Edge
To set up a nested Edge one needs to generate certificates to use when signing device certificates. These certificate will be automatically generated if not provided. These are known as quick start certificates. Providing those certificates has some advantages:
- It will stop the warning message in the `iotedge check` output.
- Edge will not need to be restarted when the quick start certificates expire.
- The Edge instance can be used as a parent to a nested Edge instance.

The certificate and key can be signed with the CertTestRoot. These are then provided in Edges config.toml file:
```toml
[edge_ca]
cert = "file://</path/to/certificate_full_chain>"  # Intermediate full chain
pk = "file://</path/to/private_key>"               # Private key
```
To establish a connection between a downstream nested Edge and this one, the top level certificate in the full chain from the certificate generated for the parent will need to be copied to the child and referenced in the *trust_bundle_cert* parameter. For example:
```toml
hostname = "<machine hostname>"
parent_hostname = "<hostname of the parent edge>"
trust_bundle_cert = "file:/</path/to/root/CA.pem>"
```
To complete a nested Edge installation, there are other actions that need to be taken but they are not certificate related.

#### Certificate Hierarchy for Above
```
Root (CA) - Specified in trust_bundle_cert in child
└──	CertTestRoot (CA)
    └─ Intermediate certificate (CA) specified in [edge_ca] on parent with the corresponding key
```
## Sample Client Device Implementations
The sample clients can by found [here](./devicesamples/).

There are only two samples. One is a device that connects to the IoT hub via DPS and the other is a device that connects directly to the IoT hub. The different scenarios are entirely driven by the launch.json file. It is recommended that you run them from Visual Studio Code.

### Hub Samples
The launch.json contains four variations with a block comment describing the required environment variables.

The self-signed and CA signed X.509 authentication use identical environment variables. The difference is in the certificates themselves. 

Similarly, the self-signed and CA signed X.509 authentication via an upstream Edge device use idenitcal environment variables. Again the difference is in the certificates themselves.

A shared access signature version is provided for completeness. 

### DPS Samples
Only one launch is contained in the launch.json file. It uses a full chain device certificate and its associated key. A block comment is provided to describe the environment variables.