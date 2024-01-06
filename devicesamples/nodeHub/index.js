// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

'use strict';

var Protocol = null;

switch ((process.env.PROTOCOL ?? 'mqtt').toUpperCase()) {
  case "MQTT":
    Protocol = require('azure-iot-device-mqtt').Mqtt;
    break;
  case "MQTTWS":
    Protocol = require('azure-iot-device-mqtt').MqttWs;
    break;
  case "AMQP":
    Protocol = require('azure-iot-device-amqp').Amqp;
    break;
  case "AMQPWS":
    Protocol = require('azure-iot-device-amqp').AmqpWs;
    break;
  case "HTTP":
    Protocol = require('azure-iot-device-http').Http;
    break;
  default:
    console.error(`Invalid protocol ${process.env.PROTOCOL} specified`);
    process.exit(4);
}
console.log(`Using protocol ${Protocol.name}`);

var Client = require('azure-iot-device').Client;
var Message = require('azure-iot-device').Message;
const fs = require('fs');

var counter = 0;

(async () => {
  var connectCallback = function (err) {
    if (err) {
      console.error('Could not connect: ' + err.message);
    } 
    else {
      console.log('Client connected');
      client.on('message', function (msg) {
        console.log('Id: ' + msg.messageId + ' Body: ' + msg.data);
        // When using MQTT the following line is a no-op.
        client.complete(msg, printResultFor('completed'));
        // The AMQP and HTTP transports also have the notion of completing, rejecting or abandoning the message.
        // When completing a message, the service that sent the C2D message is notified that the message has been processed.
        // When rejecting a message, the service that sent the C2D message is notified that the message won't be processed by the device. the method to use is client.reject(msg, callback).
        // When abandoning the message, IoT Hub will immediately try to resend it. The method to use is client.abandon(msg, callback).
        // MQTT is simpler: it accepts the message by default, and doesn't support rejecting or abandoning a message.
      });
  
      // Create a message and send it to the IoT Hub every second
      var sendInterval = setInterval(function () {
        var windSpeed = 10 + (Math.random() * 4); // range: [10, 14]
        var temperature = 20 + (Math.random() * 10); // range: [20, 30]
        var humidity = 60 + (Math.random() * 20); // range: [60, 80]
        var data = JSON.stringify({ deviceId: process.env.DEVICE_ID, windSpeed: windSpeed, temperature: temperature, humidity: humidity });
        var message = new Message(data);
        message.properties.add('temperatureAlert', (temperature > 28) ? 'true' : 'false');
  
        if (counter++ % 3 == 0) {
          message.properties.add('plusTest', 'mark+radbourne');
        }
      
        console.log('Sending message: ' + message.getData());
        client.sendEvent(message, printResultFor('send'));
      }, 2000);
  
      client.on('error', function (err) {
        console.error(err.message);
      });
  
      client.on('disconnect', function () {
        clearInterval(sendInterval);
        client.removeAllListeners();
        client.open(connectCallback);
      });
    }
  };

  var connectionString = null;
  let options = {};

  [ connectionString, options ] = generateConnectionString();
  
  var client = Client.fromConnectionString(connectionString, Protocol);

  if (Object.keys(options).length > 0) await client.setOptions(options);

  client.open(connectCallback);
})();

// Helper function to print results in the console
function printResultFor(op) {
  return function printResult(err, res) {
    if (err) console.log(op + ' error: ' + err.toString());
    if (res) console.log(op + ' status: ' + res.constructor.name);
  };
}

function generateConnectionString() {
  let connectionString = 'HostName=';
  let options = {};

  try {
    if (!process.env.HOST_NAME) {
      console.error('HOST_NAME is required');
      process.exit(4);
    }
    else {
      connectionString += process.env.HOST_NAME;
    }

    connectionString += ';DeviceId=';

    if (!process.env.DEVICE_ID) {
      console.error('DEVICE_ID is required');
      process.exit(4);
    }
    else {
      connectionString += process.env.DEVICE_ID;
    }

    if (process.env.SHARED_ACCESS_KEY) {
      connectionString += (';SharedAccessKey=' + process.env.SHARED_ACCESS_KEY);
    }
    else if (process.env.CERTIFICATE_FILE) {
      if (!process.env.KEY_FILE) {
        console.error('KEY_FILE is required with CERTIFICATE_FILE');
        process.exit(4);
      }
      connectionString += ';X509=true';
      options = {
        cert: fs.readFileSync(process.env.CERTIFICATE_FILE, { encoding: 'utf8' }),
        key: fs.readFileSync(process.env.KEY_FILE, { encoding: 'utf8' }),
      }
    }
    else {
      console.error('No authentication method has been provided');
      process.exit(4);
    }

    if (process.env.CA_FILE) {
      options.ca = process.env.CA_FILE;
    }
  }
  catch (err) {
    console.error(`Error thrown during connection string construction: ${err.message}`);
    process.exit(4);
  }

  return [ connectionString, options ];
}
