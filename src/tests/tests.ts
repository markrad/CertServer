import fs from 'fs';
import path from 'path';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import assert from 'node:assert';
import http from 'http';
import { pki } from 'node-forge';

import WebSocket from 'ws';

import { EventWaiter } from '../utility/eventWaiter';
import { OperationResult } from '../OperationResult';
import { OperationResultItem } from '../OperationResultItem';


const testPath = path.join(__dirname, '../testdata');
const testConfig = path.join(testPath, 'testconfig.yml');
const url = 'http://localhost:9997';

type response = {
    statusCode: number,
    headers: any,
    body: any,
}

const config: string = `certServer:
  root: ${testPath}
  port: 9997       
  certificate: ''  
  key: ''          
  subject:         
    C: TestCountry
    ST: TestState
    L: TestCity
    O: TestOrg
    OU: TestUnit`;

let then = new Date();
    then.setFullYear(then.getFullYear() + 1);

const newCA = {
    country: 'someCountry',
    state: 'someState',
    location: 'someLocation',
    organization: 'someOrg',
    unit: 'someUnit',
    commonName: 'someName',
    validFrom: new Date().toISOString(),
    validTo: then.toISOString(),
}

const newInt = {
    country: 'intCountry',
    state: 'intState',
    location: 'intLocation',
    organization: 'intOrg',
    unit: 'intUnit',
    commonName: 'intName',
    validFrom: new Date().toISOString(),
    validTo: then.toISOString(),
    signer: '1',
}

const newLeaf = {
    country: 'leafCountry',
    state: 'leafState',
    location: 'leafLocation',
    organization: 'leafOrg',
    unit: 'leafUnit',
    commonName: 'leafName',
    validFrom: new Date().toISOString(),
    validTo: then.toISOString(),
    signer: '2',
    SANArray: [
        "DNS: leafy.com",
        "IP: 55.55.55.55",
    ]
}

let stepNo = 0;
const types: string[] = [ 'root', 'intermediate', 'leaf', 'key'];

(async () => {
    let webServer: ChildProcessWithoutNullStreams; 
    let ws: WebSocket;
    let step = '';
    let msg: any;
    let success: boolean = true;
    try {
        // Set up
        step = _step('set up');

        if (!fs.existsSync(testPath)) fs.mkdirSync(testPath);
        fs.writeFileSync(testConfig, config);

        // Create server
        step = _step('create server');
        let ew = new EventWaiter();
        webServer = spawn('node', [ path.join(__dirname, '../index.js'), testConfig ]);

        webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
        webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
        webServer.stdout.on('data', (data) => console.log(data.toString()));

        await new Promise<void>((resolve) => setTimeout(() => resolve(), 2000));
        step = _step('connect WebSocket');
        const wsQueue: string[] = [];

        ws = new WebSocket('ws://localhost:9997');
        ws.on('error', (err) => { throw err });
        // ws.on('open', () => console.log('WebSocket open'));
        ws.on('message', (data) => {
            let dataString = data.toString();
            // console.log('message: ' + dataString);
            if (dataString != 'Connected') {
                wsQueue.push(dataString);
                ew.EventSet();
            }
        });
        ws.on('close', () => console.log('WebSocket closed'));

        let res: response;

        step = _step('check database is empty');

        for (let dir in types) {
            step = _step(`get empty ${types[dir]} list`);
            res = await httpRequest('get', url + '/api/certList?type=' + types[dir]);
            assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            assert.equal(res.body.files.length, 0, `Failed: Expected zero entries for ${types[dir]} request`);
            console.log(`Passed: zero entries returned for ${types[dir]}`);
            // console.log(JSON.stringify(res, null, 4));
        }

        step = _step('generate ca');
        res = await httpRequest('post', url + '/api/createCACert', JSON.stringify(newCA));
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'someName/someName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 1, id: 1 }, { type: 4, id: 1 }]);
        // console.log(msg);
        console.log('passed');

        step = _step('generate intermediate');
        res = await httpRequest('post', url + '/api/createIntermediateCert', JSON.stringify(newInt));
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body.error}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'intName/intName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 2, id: 2 }, { type: 4, id: 2 }]);
        // console.log(msg);
        console.log('passed');

        step = _step('generate leaf');
        res = await httpRequest('post', url + '/api/createLeafCert', JSON.stringify(newLeaf));
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 3, id: 3 }, { type: 4, id: 3 }]);
        // console.log(msg);
        console.log('passed');

        step = _step('add tags to intermediate');
        res = await httpRequest('post', url + '/api/updateCertTag?id=2', JSON.stringify({ tags: 'tag1 ; tag2' }));
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'intName', 0, 1, 0);
        checkItems(msg.updated, [{ type: 2, id: 2}]);
        console.log('passed');

        step = _step('get root certificate list');
        res = await httpRequest('get', url + '/api/certList?type=root');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        assert.notEqual(res.body.files, null, 'Did not receive the files element');
        assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        assert.equal(res.body.files[0].name, 'someName', `File has incorrect name ${res.body.files[0].name}`);
        assert.equal(res.body.files[0].type, 'root', `File has incorrect type ${res.body.files[0].type}`);
        assert.equal(res.body.files[0].id, 1, `File has incorrect id ${res.body.files[0].id}`);
        assert.deepEqual(res.body.files[0].tags, [ ], 'Tags are incorrect');
        let rootId = res.body.files[0].id;
        console.log('passed');

        step = _step('get intermediate certificate list');
        res = await httpRequest('get', url + '/api/certList?type=intermediate');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        assert.notEqual(res.body.files, null, 'Did not receive the files element');
        assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        assert.equal(res.body.files[0].name, 'intName', `File has incorrect name ${res.body.files[0].name}`);
        assert.equal(res.body.files[0].type, 'intermediate', `File has incorrect type ${res.body.files[0].type}`);
        assert.equal(res.body.files[0].id, 2, `File has incorrect id ${res.body.files[0].id}`);
        assert.deepEqual(res.body.files[0].tags, [ 'tag1', 'tag2' ], 'Tags are incorrect');
        let intId = res.body.files[0].id;
        console.log('passed');

        step = _step('get leaf certificate list');
        res = await httpRequest('get', url + '/api/certList?type=leaf');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        assert.notEqual(res.body.files, null, 'Did not receive the files element');
        assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        assert.equal(res.body.files[0].name, 'leafName', `File has incorrect name ${res.body.files[0].name}`);
        assert.equal(res.body.files[0].type, 'leaf', `File has incorrect type ${res.body.files[0].type}`);
        assert.equal(res.body.files[0].id, 3, `File has incorrect id ${res.body.files[0].id}`);
        let leafId = res.body.files[0].id;
        console.log('passed');

        step = _step('get key list');
        res = await httpRequest('get', url + '/api/keyList');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        assert.notEqual(res.body.files, null, 'Did not receive the files element');
        assert.equal(res.body.files.length, 3, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        let names = [ [ 'intName_key', 2 ], [ 'leafName_key', 3 ], [ 'someName_key', 1]  ];
        for (let i = 0; i < names.length; i++) {
            assert.equal(res.body.files[i].name, names[i][0], `File has incorrect name ${res.body.files[i].name}`)
            assert.equal(res.body.files[i].type, 'key', `File has incorrect type ${res.body.files[i].type}`);
            assert.equal(res.body.files[i].id, names[i][1], `File has incorrect id ${res.body.files[i].id}`);
        }
        console.log('passed');

        step = _step('get certificate details by id');
        res = await httpRequest('get', url + '/certDetails?id=2');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        assert.equal(res.body.certType, 'intermediate', `Wrong certificate type ${res.body.certType} returned`);
        assert.equal(res.body.id, 2, `Wrong id ${res.body.id} returned`);
        assert.equal(res.body.keyId, 2, `Wrong key id ${res.body.keyId} returned`);
        assert.equal(res.body.name, 'intName', `Wrong name ${res.body.name} returned`);
        assert.deepEqual(res.body.tags, [ 'tag1', 'tag2' ], 'Tags are incorrect');
        console.log('passed');

        step = _step('get key details by id');
        res = await httpRequest('get', url + '/keyDetails?id=3');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        console.log('passed');

        step = _step('check database is populated');
        
        for (let dir in types) {
            step = _step(`get populated ${types[dir]} list`);
            res = await httpRequest('get', url + '/certList?type=' + types[dir]);
            assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            if (dir != '3') {
                assert.equal(res.body.files.length, 1, `Failed: Expected one entry for ${types[dir]} request`);
                console.log(`Passed: one entry returned for ${types[dir]}`);
            }
            else {
                assert.equal(res.body.files.length, 3, `Failed: Expected three entries for ${types[dir]} request`);
                console.log(`Passed: three entries returned for ${types[dir]}`);
            }
            // console.log(JSON.stringify(res, null, 4));
        }
        
        step = _step('get root certificate file');
        res = await httpRequest('get', url + '/api/getCertificatePem?id=' + rootId.toString());
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs.writeFileSync(path.join(testPath, 'someName.pem'), res.body);
        let rootCert = pki.certificateFromPem(res.body);
        let rski = rootCert.getExtension('subjectKeyIdentifier');
        console.log(JSON.stringify(rski, null, 4));
        console.log('passed');
        
        step = _step('get intermediate certificate file');
        res = await httpRequest('get', url + '/api/getCertificatePem?id=' + intId.toString());
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs.writeFileSync(path.join(testPath, 'intName.pem'), res.body);
        let intermediateCert = pki.certificateFromPem(res.body);
        let iski = intermediateCert.getExtension('subjectKeyIdentifier');
        let iaki = intermediateCert.getExtension('authorityKeyIdentifier');
        assert.equal((rski as any).value.slice(1), (iaki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');
        
        step = _step('get leaf certificate file');
        res = await httpRequest('get', url + '/api/getCertificatePem?id=' + leafId.toString());
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs.writeFileSync(path.join(testPath, 'leafName.pem'), res.body);
        let leafCert = pki.certificateFromPem(res.body);
        let laki = leafCert.getExtension('authorityKeyIdentifier');
        assert.equal((iski as any).value.slice(1), (laki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');

        step = _step('get intermediate key file');
        res = await httpRequest('get', url + '/api/getKeyPem?id=2');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs.writeFileSync(path.join(testPath, 'intName_key.pem'), res.body);

        step = _step('delete root certificate');
        res = await httpRequest('delete', url + '/api/deleteCert?name=someName');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, '', 0, 2, 1);
        checkItems(msg.updated, [{ type: 4, id: 1 }, { type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 1, id: 1 }]);
        res = await httpRequest('get', url + '/certDetails?id=2');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        assert.equal(res.body.signerId, null, 'Signed certificate still references nonexistent parent');
        // console.log(msg);
        console.log('passed');

        step = _step('Upload root certificate');
        let cert = fs.readFileSync(path.join(testPath, 'someName.pem'), { encoding: 'utf8' });
        res = await httpRequest('post', url + '/api/uploadCert', cert, 'text/plain');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'someName', 1, 2, 0);
        checkItems(msg.added, [{ type: 1, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id: 2 }, { type: 4, id: 1 }]);
        res = await httpRequest('get', url + '/certDetails?id=2');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        assert.equal(res.body.signerId, 4, 'Signed certificate does not reference uploaded parent');
        console.log('passed')

        step = _step('delete intermediate key');
        res = await httpRequest('delete', url + '/api/deleteKey?name=intName_key');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, '', 0, 1, 1);
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 4, id: 2 }]);
        // console.log(msg);
        console.log('passed');

        step = _step('Upload intermediate key');
        let key = fs.readFileSync(path.join(testPath, 'intName_key.pem'), { encoding: 'utf8' });
        res = await httpRequest('post', url + '/api/uploadKey', key, 'text/plain');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        checkPacket(msg, 'intName_key', 1, 1, 0);
        checkItems(msg.added, [{ type: 4, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id:2 }]);
        console.log('passed')

        step = _step('get certificate with no name or id');
        res = await httpRequest('get', url + '/api/getCertificatePem?xx=bad');
        assert.equal(res.statusCode, 400, 'This should have failed');
        console.log('passed');

        step = _step('get certificate with name not found');
        res = await httpRequest('get', url + '/api/getCertificatePem?name=bad');
        assert.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');

        step = _step('get certificate with id not found');
        res = await httpRequest('get', url + '/api/getCertificatePem?id=bad');
        assert.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');

        step = _step('tests complete');
    }
    catch (err) {
        console.log(`**** Failed in step ${step}: ${err.message}`);
        success = false;
    }
    finally {
        step = _step('cleanup');

        step = _step('disconnect WebSocket');
        ws.close();

        step = _step('kill server');
        webServer.kill('SIGTERM');

        step = _step('remove files');
        fs.unlinkSync(path.join(testPath, 'testconfig.yml'));
        fs.rmSync(testPath, { recursive: true, force: true });
        step = _step('finish');
        process.exit(success? 0 : 4);
    }
})();

function checkPacket(packet: OperationResult, name: string, added: number, updated: number, deleted: number): void {
    assert.equal(packet.name, name, `Failed: Incorrect certificate/key names - expected ${name}, received ${packet.name}`);
    assert.equal(packet.added.length, added, `Incorrect added length - expected ${added}, received ${packet.added.length}`);
    assert.equal(packet.updated.length, updated, `Incorrect updated length - expected ${updated}, received ${packet.updated.length}`);
    assert.equal(packet.deleted.length, deleted, `Incorrect deleted length - expected ${deleted}, received ${packet.deleted.length}`);
}

function checkItems(items: OperationResultItem[], test: OperationResultItem[]) {
    assert.equal(items.length, test.length, `Entry counts do not match - ${test.length}, received ${items.length}`);

    for (let i = 0; i < items.length; i++) {
        assert.deepStrictEqual(items[i], test[i], `Item type ${i} does not match the test version`);
    }
}

function _step(msg: string): string {
    console.log(`\nStep: ${++stepNo}: ${msg}`);
    return msg;
}

async function httpRequest(method: 'get' | 'post' | 'delete' | 'head', url: URL | string, body: string = null, contentType: string = 'application/json'): Promise<response> {
    return new Promise<response>((resolve, reject) => {
        if (!['get', 'post', 'head', 'delete'].includes(method)) {
            reject(new Error(`Invalid method: ${method}`));
        }

        let urlObject;

        try {
            urlObject = new URL(url);
        } 
        catch (error) {
            reject(new Error(`Invalid url ${url}`));
        }

        if (body && method !== 'post') {
            reject(new Error(`Invalid use of the body parameter while using the ${method.toUpperCase()} method.`));
        }

        let options = {
            method: method.toUpperCase(),
            hostname: urlObject.hostname,
            port: urlObject.port,
            path: urlObject.pathname,
            headers: {},
        };

        if (body) {
            options.headers = { 'Content-Length': Buffer.byteLength(body), 'Content-Type': contentType };
        }

        const clientRequest = http.request(url, { method: method.toUpperCase(), headers: options.headers }, incomingMessage => {

            // Response object.
            let response: response = {
                statusCode: incomingMessage.statusCode,
                headers: incomingMessage.headers,
                body: '',
            };

            // Collect response body data.
            incomingMessage.on('data', chunk => {
                response.body += chunk;
            });

            // Resolve on end.
            incomingMessage.on('end', () => {
                if (response.body.length) {
                    try {
                        response.body = JSON.parse(response.body);
                    } catch (error) {
                        // Silently fail if response is not JSON.
                    }
                }

                resolve(response);
            });
        });
        
        // Reject on request error.
        clientRequest.on('error', error => {
            reject(error);
        });

        // Write request body if present.
        if (body) {
            clientRequest.write(body);
        }

        // Close HTTP connection.
        clientRequest.end();
    });
}