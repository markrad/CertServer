// Experimental piece of code that could be utilized in the samples to directly acquire the certificates
// and keys from the server rather than having to copy them to the local machine.

const https = require('https');
const http = require('http');
const path = require('path');
const { url } = require('inspector');

async function getCerts(certServer, certId, keyId) {
    return new Promise(async (resolve, reject) => {
        try {
            let cert = await httpPromise(new URL(`/api/ChainDownload?id=${certId}`, certServer));
            let key = await httpPromise(new URL(`/api/getKeyPem?id=${keyId}`, certServer));
            resolve({ cert: cert, key: key });
        }
        catch (err) {
            reject(err);
        }
    });
}

async function getTrust(certServer, certId) {
    return new Promise(async (resolve, reject) => {
        try {
            let cert = await httpPromise(new URL(`/api/getCertificatePem?id=${certId}`, certServer).toString());
            resolve(cert);
        }
        catch (err) {
            reject(err);
        }
    });
}

async function httpPromise(url) {
    return new Promise((resolve, reject) => {
        let h = url.protocol == 'https'? https : http;
        if (url.protocol) {
            h.get(url, (res) => {
                let data = '';
                res.on('data', (d) => data += d);
                res.on('end', () => resolve(data));
                res.on('error', (err) => reject(err));
            });
        }
    });
}

module.exports = { getCerts, getTrust };