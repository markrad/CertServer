'use strict';

var Client = require('azure-iot-device').Client;
var Message = require('azure-iot-device').Message;

var fs = require('fs');

var IoTHubTransport = null;
var Protocol = null;

switch ((process.env.PROTOCOL ?? 'mqtt').toUpperCase()) {
  case "MQTT":
    Protocol = require('azure-iot-provisioning-device-mqtt').Mqtt;
    IoTHubTransport = require('azure-iot-device-mqtt').Mqtt;
    break;
  case "MQTTWS":
    Protocol = require('azure-iot-provisioning-device-mqtt').MqttWs;
    IoTHubTransport = require('azure-iot-device-mqtt').MqttWs;
    break;
  case "AMQP":
    Protocol = require('azure-iot-provisioning-device-amqp').Amqp;
    IoTHubTransport = require('azure-iot-device-amqp').Amqp;
    break;
  case "AMQPWS":
    Protocol = require('azure-iot-provisioning-device-amqp').AmqpWs;
    IoTHubTransport = require('azure-iot-device-amqp').AmqpWs;
    break;
  case "HTTP":
    Protocol = require('azure-iot-provisioning-device-http').Http;
    IoTHubTransport = require('azure-iot-device-http').Http;
    break;
  default:
    console.error(`Invalid protocol ${process.env.PROTOCOL} specified`);
    process.exit(4);
}
console.log(`Using protocol ${Protocol.name}`);

var X509Security = require('azure-iot-security-x509').X509Security;
var ProvisioningDeviceClient = require('azure-iot-provisioning-device').ProvisioningDeviceClient;

var provisioningHost = process.env.PROVISIONING_HOST;
var idScope = process.env.PROVISIONING_IDSCOPE;
var registrationId = process.env.PROVISIONING_REGISTRATION_ID;
var deviceCert = {
    cert: fs.readFileSync(process.env.CERTIFICATE_FILE, { encoding: 'utf8' }),
    key: fs.readFileSync(process.env.KEY_FILE, { encoding: 'utf8' })
};

var transport = new Protocol();
var securityClient = new X509Security(registrationId, deviceCert);
var deviceClient = ProvisioningDeviceClient.create(provisioningHost, idScope, transport, securityClient);

// Register the device.  Do not force a re-registration.
deviceClient.register(function(err, result) {
    if (err) {
        console.log("error registering device: " + err);
    } 
    else {
        console.log('registration succeeded');
        console.log('assigned hub=' + result.assignedHub);
        console.log('deviceId=' + result.deviceId);
        var connectionString = 'HostName=' + result.assignedHub + ';DeviceId=' + result.deviceId + ';x509=true';
        var hubClient = Client.fromConnectionString(connectionString, IoTHubTransport);
        hubClient.setOptions(deviceCert);
        hubClient.open(function(err) {
            if (err) {
                console.error('Failure opening iothub connection: ' + err.message);
            } 
            else {
                console.log('Client connected');
                let i = 0;
                let sender = () => {
                    var msg = { index: i++ };
                    var message = new Message(JSON.stringify(msg));
                    hubClient.sendEvent(message, (err, res) => {
                        if (err) { 
                            console.log('Send error: ' + err.toString());
                            process.exit(1);
                        }
                        else if (res) {
                            console.log('Send status: ' + res.constructor.name + ': ' + JSON.stringify(msg));
                        }
                        else {
                            console.log('Unknown error');
                            process.exit(1);
                        }
                    });
                    setTimeout(sender, 5000);
                }
                sender();
            }
        });
    }
});
