import fs from 'fs';
import path from 'path';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';
import assert from 'node:assert';
import http from 'http';
import { pki } from 'node-forge';

import WebSocket from 'ws';

import { EventWaiter } from '../utility/eventWaiter';
import { OperationResult } from '../webservertypes/OperationResult';
import { OperationResultItem } from '../webservertypes/OperationResultItem';


const testPath = path.join(__dirname, '../testdata');
const testConfig = path.join(testPath, 'testconfig.yml');
const url = 'http://localhost:9997';

type Response = {
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
    C: US
    ST: TestState
    L: TestCity
    O: TestOrg
    OU: TestUnit`;

let then = new Date();
    then.setFullYear(then.getFullYear() + 1);

const newCA = {
    country: 'US',
    state: 'someState',
    location: 'someLocation',
    organization: 'someOrg',
    unit: 'someUnit',
    commonName: 'someName',
    validFrom: new Date().toISOString(),
    validTo: then.toISOString(),
}

const newInt = {
    country: 'US',
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
    country: 'US',
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

type Test = {
    description: string,
    runOnFailure: boolean,
    testFunction: () => boolean | Promise<boolean>,
    result: boolean,
}

let tests: Test[] = [
    { description: 'Set up', runOnFailure: true, testFunction: setup, result: true },
    { description: 'Create webserver', runOnFailure: true, testFunction: createWebserver, result: true },
    { description: 'Connect WebSocket', runOnFailure: true, testFunction: connectWebSocket, result: true },
    { description: 'Ensure the database is empty', runOnFailure: false, testFunction: checkForEmptyDatabase, result: true },
    { description: 'Generate CA certificate', runOnFailure: false, testFunction: createCACertificate, result: true },
    { description: 'Generate intermediate certificate', runOnFailure: false, testFunction: createIntermediateCertificate, result: true },
    { description: 'Generate leaf certificate', runOnFailure: false, testFunction: createLeafCertificate, result: true },
    { description: 'Add tags to intermediate certificate', runOnFailure: false, testFunction: addTagsToIntermediate, result: true },
    { description: 'Get a list of the root certificates', runOnFailure: false, testFunction: getRootCertificateList, result: true },
    { description: 'Get a list of the intermediate certificates', runOnFailure: false, testFunction: getIntermediateCertificateList, result: true },
    { description: 'Get a list of the leaf certificates', runOnFailure: false, testFunction: getLeafCertificateList, result: true },
    { description: 'Get a list of the keys', runOnFailure: false, testFunction: getKeyList, result: true },
    { description: 'Get certificate details by ID', runOnFailure: false, testFunction: getCertificateDetailsByID, result: true },
    { description: 'Get key details by ID', runOnFailure: false, testFunction: getKeyDetailsByID, result: true },
    { description: 'Check the database is populated', runOnFailure: false, testFunction: checkDatabaseIsPopulated, result: true },
    { description: 'Get root certificate file', runOnFailure: false, testFunction: getRootCertificateFile, result: true },
    { description: 'Get intermediate certificate file', runOnFailure: false, testFunction: getIntermediateCertificateFile, result: true },
    { description: 'Get leaf certificate file', runOnFailure: false, testFunction: getLeafCertificateFile, result: true },
    { description: 'Get key file', runOnFailure: false, testFunction: getKeyFile, result: true },
    { description: 'Delete root certificate', runOnFailure: false, testFunction: deleteRootCertificate, result: true },
    { description: 'Upload root certificate', runOnFailure: false, testFunction: uploadRootCertificate, result: true },
    { description: 'Delete intermediate key', runOnFailure: false, testFunction: deleteIntermediateKey, result: true },
    { description: 'Delete intermediate key', runOnFailure: false, testFunction: uploadIntermediateKey, result: true },
    { description: 'Get certificate with bad parameters', runOnFailure: false, testFunction: getCertificateWithBadParameter, result: true },
    { description: 'Get certificate with nonexistent name', runOnFailure: false, testFunction: getCertificateWithNonexistentName, result: true },
    { description: 'Get certificate with nonexistent Id', runOnFailure: false, testFunction: getCertificateWithNonexistentId, result: true },
    { description: 'Clean up', runOnFailure: true, testFunction: cleanUp, result: true },
];

const types: string[] = [ 'root', 'intermediate', 'leaf', 'key'];
let webServer: ChildProcessWithoutNullStreams; 
let ws: WebSocket;
let ew: EventWaiter;
let res: Response;
const wsQueue: string[] = [];       // Used to pass data from WebSocket on message function to main thread
let msg: any;
let rski: {};
let iski: {};

async function setup():  Promise<boolean> {
    if (!fs.existsSync(testPath)) fs.mkdirSync(testPath);
    fs.writeFileSync(testConfig, config);
    return true;
}

async function createWebserver(): Promise<boolean> {
    ew = new EventWaiter();
    webServer = spawn('node', [ path.join(__dirname, '../index.js'), testConfig ]);
    webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
    webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
    webServer.stdout.on('data', (data) => console.log(data.toString()));
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 2000));
    return true;
}

async function connectWebSocket(): Promise<boolean> {

    let ewLocal: EventWaiter = new EventWaiter();
    ws = new WebSocket('ws://localhost:9997');
    ws.on('error', (err) => { throw err });
    ws.on('open', () => {
        console.log('WebSocket open');
        ewLocal.EventSet();
    });
    ws.on('message', (data) => {
        let dataString = data.toString();
        if (dataString != 'Connected') {
            wsQueue.push(dataString);
            ew.EventSet();
        }
    });
    ws.on('close', () => console.log('WebSocket closed'));
    await ewLocal.EventWait();
    return true;
}

async function checkForEmptyDatabase(): Promise<boolean> {
    
    for (let dir in types) {
        res = await httpRequest('get', url + '/api/certList?type=' + types[dir]);
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        assert.equal(res.body.files.length, 0, `Failed: Expected zero entries for ${types[dir]} request`);
        console.log(`Passed: zero entries returned for ${types[dir]}`);
    }
    return true;
}

async function createCACertificate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/createCACert', JSON.stringify(newCA));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'someName/someName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 1, id: 1 }, { type: 4, id: 1 }]);
    console.log('passed');
    return true;
}

async function createIntermediateCertificate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/createIntermediateCert', JSON.stringify(newInt));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body.error}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'intName/intName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 2, id: 2 }, { type: 4, id: 2 }]);
    console.log('passed');
    return true;
}

async function createLeafCertificate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/createLeafCert', JSON.stringify(newLeaf));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 3, id: 3 }, { type: 4, id: 3 }]);
    console.log('passed');
    return true;
}

async function addTagsToIntermediate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/updateCertTag?id=2', JSON.stringify({ tags: [ 'tag1', 'tag2' ] }));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'intName', 0, 1, 0);
    checkItems(msg.updated, [{ type: 2, id: 2}]);
    console.log('passed');
    return true;
}

async function getRootCertificateList(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/certList?type=root');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
    assert.notEqual(res.body.files, null, 'Did not receive the files element');
    assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
    assert.equal(res.body.files[0].name, 'someName', `File has incorrect name ${res.body.files[0].name}`);
    assert.equal(res.body.files[0].type, 'root', `File has incorrect type ${res.body.files[0].type}`);
    assert.equal(res.body.files[0].id, 1, `File has incorrect id ${res.body.files[0].id}`);
    assert.equal(res.body.files[0].keyId, 1, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
    assert.deepEqual(res.body.files[0].tags, [ ], 'Tags are incorrect');
    console.log('passed');
    return true;
}

async function getIntermediateCertificateList(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/certList?type=intermediate');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
    assert.notEqual(res.body.files, null, 'Did not receive the files element');
    assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
    assert.equal(res.body.files[0].name, 'intName', `File has incorrect name ${res.body.files[0].name}`);
    assert.equal(res.body.files[0].type, 'intermediate', `File has incorrect type ${res.body.files[0].type}`);
    assert.equal(res.body.files[0].id, 2, `File has incorrect id ${res.body.files[0].id}`);
    assert.equal(res.body.files[0].keyId, 2, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
    assert.deepEqual(res.body.files[0].tags, [ 'tag1', 'tag2' ], 'Tags are incorrect');
    console.log('passed');
    return true;
}

async function getLeafCertificateList(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/certList?type=leaf');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
    assert.notEqual(res.body.files, null, 'Did not receive the files element');
    assert.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
    assert.equal(res.body.files[0].name, 'leafName', `File has incorrect name ${res.body.files[0].name}`);
    assert.equal(res.body.files[0].type, 'leaf', `File has incorrect type ${res.body.files[0].type}`);
    assert.equal(res.body.files[0].id, 3, `File has incorrect id ${res.body.files[0].id}`);
    assert.equal(res.body.files[0].keyId, 3, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
    console.log('passed');
    return true;
}

async function getCertificateDetailsByID(): Promise<boolean> {
    res = await httpRequest('get', url + '/certDetails?id=2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    assert.equal(res.body.certType, 'intermediate', `Wrong certificate type ${res.body.certType} returned`);
    assert.equal(res.body.id, 2, `Wrong id ${res.body.id} returned`);
    assert.equal(res.body.keyId, 2, `Wrong key id ${res.body.keyId} returned`);
    assert.equal(res.body.name, 'intName', `Wrong name ${res.body.name} returned`);
    assert.deepEqual(res.body.tags, [ 'tag1', 'tag2' ], 'Tags are incorrect');
    console.log('passed');
    return true;
    }
    
async function getKeyDetailsByID(): Promise<boolean> {
    res = await httpRequest('get', url + '/keyDetails?id=3');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    console.log('passed');
    return true;
}

async function checkDatabaseIsPopulated(): Promise<boolean> {
    for (let dir in types) {
        console.log(`get populated ${types[dir]} list`);
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
    }
    return true;
}

async function getKeyList(): Promise<boolean> {
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
    return true;
}
        
async function getRootCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' + '1');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    fs.writeFileSync(path.join(testPath, 'someName.pem'), res.body);
    let rootCert = pki.certificateFromPem(res.body);
    rski = rootCert.getExtension('subjectKeyIdentifier');
    console.log(JSON.stringify(rski, null, 4));
    console.log('passed');
    return true;
}

async function getIntermediateCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' +'2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    fs.writeFileSync(path.join(testPath, 'intName.pem'), res.body);
    let intermediateCert = pki.certificateFromPem(res.body);
    iski = intermediateCert.getExtension('subjectKeyIdentifier');
    let iaki = intermediateCert.getExtension('authorityKeyIdentifier');
    assert.equal((rski as any).value.slice(1), (iaki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
    console.log('passed');
    return true;
}
async function getLeafCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' + '3');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    fs.writeFileSync(path.join(testPath, 'leafName.pem'), res.body);
    let leafCert = pki.certificateFromPem(res.body);
    let laki = leafCert.getExtension('authorityKeyIdentifier');
    assert.equal((iski as any).value.slice(1), (laki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
    console.log('passed');
    return true;
}

async function getKeyFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getKeyPem?id=2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    fs.writeFileSync(path.join(testPath, 'intName_key.pem'), res.body);
    return true;
}

async function deleteRootCertificate(): Promise<boolean> {
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
    console.log('passed');
    return true;
}

async function uploadRootCertificate(): Promise<boolean> {
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
    return true;
}

async function deleteIntermediateKey(): Promise<boolean> {
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
    return true;
}

async function uploadIntermediateKey(): Promise<boolean> {
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
    return true;
}

async function getCertificateWithBadParameter(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?xx=bad');
    assert.equal(res.statusCode, 400, 'This should have failed');
    console.log('passed');
    return true;
}

async function getCertificateWithNonexistentName(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?name=bad');
    assert.equal(res.statusCode, 404, 'This should have failed');
    console.log('passed');
    return true;
}

async function getCertificateWithNonexistentId(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=bad');
    assert.equal(res.statusCode, 404, 'This should have failed');
    console.log('passed');
    return true;
}

async function cleanUp(): Promise<boolean> {
    ws.close();
    webServer.kill('SIGTERM');
    fs.unlinkSync(path.join(testPath, 'testconfig.yml'));
    fs.rmSync(testPath, { recursive: true, force: true });

    return true;
}

runTests();

async function runTests() {
    console.log(`Running ${tests.length} test${tests.length == 1? '' : 's'}`);

    for (let test in tests) {
        let succeeded = tests.map((entry) => entry.result).reduce((previousValue, currentValue): boolean => {
            return currentValue == false? currentValue : previousValue;
        }, true);
        let run = (succeeded == true || tests[test].runOnFailure == true)
        console.log(`Test ${test}: ${tests[test].description} ${run? '' : ' - Skipped due to previous failure'}`);
        if (run) {
            try {
                tests[test].result = await tests[test].testFunction();
                if (!tests[test].result) {
                    console.error(`Test ${test}: failed`);
                }
                else {
                    console.log(`Test ${test}: succeeded`);
                }
            }
            catch (err) {
                console.error(`Error caught in test ${test} - ${err.message}`);
                tests[test].result = false;
            }
        }
    }

    let failedCount = tests.filter((entry) => !entry.result );

    if (failedCount.length > 0) {
        console.error(`The following test${failedCount.length == 1? '' : 's'} failed:`);
        for (let test in tests) {
            if (!tests[test].result) {
                console.error(`${test} - ${tests[test].description}`);
            }
        }
        console.error(`${failedCount.length} test${failedCount.length == 1? '' : 's'} failed`);
        process.exit(4);
    }
    else {
        console.log('All tests passed');
    }
}

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

async function httpRequest(method: 'get' | 'post' | 'delete' | 'head', url: URL | string, body: string = null, contentType: string = 'application/json'): Promise<Response> {
    return new Promise<Response>((resolve, reject) => {
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
            let response: Response = {
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
