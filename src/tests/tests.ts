import fs from 'fs';
import { rm, unlink, mkdir, writeFile, readFile } from 'fs/promises';
import path from 'path';
import { spawn, ChildProcessWithoutNullStreams, execSync } from 'child_process';
import assert from 'node:assert';
import http, { OutgoingHttpHeaders } from 'http';
import https from 'https';
import { pki } from 'node-forge';
import { Readable } from 'stream';
import readline from 'node:readline';
import { stdin as input, stdout as output } from 'node:process';

import WebSocket from 'ws';
// import * as wtfnode from 'wtfnode';

import { EventWaiter } from '../utility/eventWaiter';
import { OperationResult } from '../webservertypes/OperationResult';
import { OperationResultItem } from '../webservertypes/OperationResultItem';
import { getSASToken, ConnectionInfo } from '../utility/generatesastoken'


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

const bashHelperScript = 'bashHelper.sh';
const pwshHelperScript = 'pwshHelper.ps1';

enum TestType {
    NoRun = 0,
    RunForAPITests = 1,
    RunForBashTests = 2,
    RunForPowerShellTests = 4,
    RunForAllTests = RunForAPITests + RunForBashTests + RunForPowerShellTests
}

type Test = {
    description: string,
    runCondition: TestType,
    runRequiresSASToken?: boolean,
    runOnFailure: boolean,
    testFunction: () => boolean | Promise<boolean>,
    result: TestResult,
}

type ShellInfo = {
    available: boolean,
    command: string,
    scriptLoc: string,
    sourceCmd: string,
    consoleOutCmd: string,
    consolePostProcessor: (line: string) => string,
}

type Shells = {
    bash: ShellInfo
    powershell: ShellInfo
}

let shells: Shells;
let sasToken: ConnectionInfo = null;
let connectionString: string;

enum TestResult {
    TestNotYetRun,
    TestSucceeded,
    TestFailed,
    TestSkippedNotSelected,
    TestSkippedNoEnvironment,
    TestSkippedPlaceHolder,
    TestSkippedPreviousFailure,
    TestSkippedMissingOrInvalidConnectionString,
}

let tests: Test[] = [
    { description: 'Set up', runCondition: TestType.RunForAllTests, runOnFailure: true, testFunction: setup, result: TestResult.TestNotYetRun },
    { description: 'Create webserver', runCondition: TestType.RunForAllTests, runOnFailure: true, testFunction: createWebserver, result: TestResult.TestNotYetRun },
    { description: 'Connect WebSocket', runCondition: TestType.RunForAllTests, runOnFailure: true, testFunction: connectWebSocket, result: TestResult.TestNotYetRun },
    { description: 'Ensure the database is empty', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: checkForEmptyDatabase, result: TestResult.TestNotYetRun },
    { description: 'Generate CA certificate', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: createCACertificate, result: TestResult.TestNotYetRun },
    { description: 'Generate intermediate certificate', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: createIntermediateCertificate, result: TestResult.TestNotYetRun },
    { description: 'Generate leaf certificate', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: createLeafCertificate, result: TestResult.TestNotYetRun },
    { description: 'Add tags to intermediate certificate', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: addTagsToIntermediate, result: TestResult.TestNotYetRun },
    { description: 'Get a list of the root certificates', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getRootCertificateList, result: TestResult.TestNotYetRun },
    { description: 'Get a list of the intermediate certificates', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getIntermediateCertificateList, result: TestResult.TestNotYetRun },
    { description: 'Get a list of the leaf certificates', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getLeafCertificateList, result: TestResult.TestNotYetRun },
    { description: 'Get a list of the keys', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getKeyList, result: TestResult.TestNotYetRun },
    { description: 'Get certificate details by ID', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getCertificateDetailsByID, result: TestResult.TestNotYetRun },
    { description: 'Get key details by ID', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getKeyDetailsByID, result: TestResult.TestNotYetRun },
    { description: 'Check the database is populated', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: checkDatabaseIsPopulated, result: TestResult.TestNotYetRun },
    { description: 'Get root certificate file', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getRootCertificateFile, result: TestResult.TestNotYetRun },
    { description: 'Get intermediate certificate file', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getIntermediateCertificateFile, result: TestResult.TestNotYetRun },
    { description: 'Get leaf certificate file', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getLeafCertificateFile, result: TestResult.TestNotYetRun },
    { description: 'Get leaf chain file', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getLeafChainFile, result: TestResult.TestNotYetRun },
    { description: 'Get key file', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getKeyFile, result: TestResult.TestNotYetRun },
    { description: 'Get certificate with bad parameters', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getCertificateWithBadParameter, result: TestResult.TestNotYetRun },
    { description: 'Get certificate with nonexistent name', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getCertificateWithNonexistentName, result: TestResult.TestNotYetRun },
    { description: 'Get certificate with nonexistent Id', runCondition: TestType.RunForAPITests, runOnFailure: false, testFunction: getCertificateWithNonexistentId, result: TestResult.TestNotYetRun },
    { description: 'Delete root certificate', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: deleteRootCertificate, result: TestResult.TestNotYetRun },
    { description: 'Upload root certificate', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: uploadRootCertificate, result: TestResult.TestNotYetRun },
    { description: 'Delete intermediate key', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: deleteIntermediateKey, result: TestResult.TestNotYetRun },
    { description: 'Upload intermediate key', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: uploadIntermediateKey, result: TestResult.TestNotYetRun },
    // bash script section
    { description: '[bash] Download and source bash helper script', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashDownloadAndSource, result: TestResult.TestNotYetRun },
    { description: '[bash] Ensure urlencode works', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashTestUrlEncode, result:TestResult.TestNotYetRun },
    { description: '[bash] Ensure environment variable points to server', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashGetServer, result: TestResult.TestNotYetRun},
    { description: '[bash] Get service statistics', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: false, testFunction: bashGetIoTStats, result: TestResult.TestNotYetRun},
    { description: '[bash] Connect to hub with garbage connection string', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: false, testFunction: bashContactHubWithGarbageConnectionString, result: TestResult.TestNotYetRun },
    { description: '[bash] Connect to hub with bad connection string', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: false, testFunction: bashContactHubWithBadConnectionString, result: TestResult.TestNotYetRun },
    { description: '[bash] Create device and X.509 authorization files', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: false, testFunction: bashGenDevice, result: TestResult.TestNotYetRun },
    { description: '[bash] Delete device created by above', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: true, testFunction: bashRemDevice, result: TestResult.TestNotYetRun },
    // PowerShell script section
    { description: '[pwsh] Download and source PowerShell helper script', runCondition: TestType.RunForPowerShellTests, runOnFailure: false, testFunction: pwshDownloadAndSource, result: TestResult.TestNotYetRun },
    { description: '[pwsh] Ensure environment variable points to server', runCondition: TestType.RunForPowerShellTests, runOnFailure: false, testFunction: pwshGetServer, result: TestResult.TestNotYetRun },
    { description: '[pwsh] Get service statistics', runCondition: TestType.RunForPowerShellTests, runRequiresSASToken: true, runOnFailure: false, testFunction: pwshGetIoTStats, result: TestResult.TestNotYetRun },
    { description: '[pwsh] Create device and X.509 authorization files', runCondition: TestType.RunForPowerShellTests, runRequiresSASToken: true, runOnFailure: false, testFunction: pwshGenDevice, result: TestResult.TestNotYetRun },
    { description: '[pwsh] Delete device created by above', runCondition: TestType.RunForPowerShellTests, runRequiresSASToken: true, runOnFailure: false, testFunction: pwshRemDevice, result: TestResult.TestNotYetRun },
    // Clean up section
    { description: 'Clean up', runCondition: TestType.RunForAPITests, runOnFailure: true, testFunction: cleanUp, result: TestResult.TestNotYetRun },
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
    if (!fs.existsSync(testPath)) await mkdir(testPath);
    await writeFile(testConfig, config);
    return true;
}

async function createWebserver(): Promise<boolean> {
    ew = new EventWaiter();
    webServer = spawn('node', [ path.join(__dirname, '../index.js'), testConfig ]);
    webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
    webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
    webServer.stdout.on('data', (data) => { if (process.env.LOG_SERVER_STDOUT == "1") console.log(data.toString().trimEnd()); });
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
    res = await httpRequest('post', url + '/api/createCACert', null, JSON.stringify(newCA));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'someName/someName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 1, id: 1 }, { type: 4, id: 1 }]);
    return true;
}

async function createIntermediateCertificate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/createIntermediateCert', null, JSON.stringify(newInt));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body.error}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'intName/intName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 2, id: 2 }, { type: 4, id: 2 }]);
    return true;
}

async function createLeafCertificate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/createLeafCert', null, JSON.stringify(newLeaf));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
    checkItems(msg.added, [{ type: 3, id: 3 }, { type: 4, id: 3 }]);
    return true;
}

async function addTagsToIntermediate(): Promise<boolean> {
    res = await httpRequest('post', url + '/api/updateCertTag?id=2', null, JSON.stringify({ tags: [ 'tag1', 'tag2' ] }));
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'intName', 0, 1, 0);
    checkItems(msg.updated, [{ type: 2, id: 2}]);
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
    return true;
}

async function getCertificateDetailsByID(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/certDetails?id=2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    assert.equal(res.body.certType, 'intermediate', `Wrong certificate type ${res.body.certType} returned`);
    assert.equal(res.body.id, 2, `Wrong id ${res.body.id} returned`);
    assert.equal(res.body.keyId, 2, `Wrong key id ${res.body.keyId} returned`);
    assert.equal(res.body.name, 'intName', `Wrong name ${res.body.name} returned`);
    assert.deepEqual(res.body.tags, [ 'tag1', 'tag2' ], 'Tags are incorrect');
    return true;
}
    
async function getKeyDetailsByID(): Promise<boolean> {
    res = await httpRequest('get', url + '/keyDetails?id=3');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
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
    return true;
}
        
async function getRootCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' + '1');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await writeFile(path.join(testPath, 'someName.pem'), res.body);
    let rootCert = pki.certificateFromPem(res.body);
    rski = rootCert.getExtension('subjectKeyIdentifier');
    return true;
}

async function getIntermediateCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' +'2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await writeFile(path.join(testPath, 'intName.pem'), res.body);
    let intermediateCert = pki.certificateFromPem(res.body);
    iski = intermediateCert.getExtension('subjectKeyIdentifier');
    let iaki = intermediateCert.getExtension('authorityKeyIdentifier');
    assert.equal((rski as any).value.slice(1), (iaki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
    return true;
}

async function getLeafCertificateFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=' + '3');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await writeFile(path.join(testPath, 'leafName.pem'), res.body);
    let leafCert = pki.certificateFromPem(res.body);
    let laki = leafCert.getExtension('authorityKeyIdentifier');
    assert.equal((iski as any).value.slice(1), (laki as any).value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
    let san: any = leafCert.getExtension('subjectAltName');
    assert.notEqual(san, null, 'Failed to get the subject alternate names');
    assert.equal(san.altNames.length, 3, 'Incorrect number of alt names on leaf');
    assert.deepEqual(san.altNames, [{ type: 2, value: 'leafName' }, { type: 2, value: 'leafy.com' }, { type: 7, value: "7777", ip: '55.55.55.55' }], 'Alt names do not match expected list');
    return true;
}

async function getLeafChainFile(): Promise<boolean> {
    let certHeader = '-----BEGIN CERTIFICATE-----';
    res = await httpRequest('get', url + '/api/chainDownload?id=' + '3');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    let filename = res.headers['content-disposition'].split('=')[1];
    assert.equal('leafName_chain.pem', filename, 'The content-disposition header was incorrect');
    assert.equal(res.body.split(certHeader).length, 4, `Incorrect number of certificates returned in chain: ${res.body.split(certHeader).length}`);
    return true;
}

async function getKeyFile(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getKeyPem?id=2');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await writeFile(path.join(testPath, 'intName_key.pem'), res.body);
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
    return true;
}

async function uploadRootCertificate(): Promise<boolean> {
    let cert = await readFile(path.join(testPath, 'someName.pem'), { encoding: 'utf8' });
    res = await httpRequest('post', url + '/api/uploadCert', null, cert, 'text/plain');
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
    return true;
}

async function uploadIntermediateKey(): Promise<boolean> {
    let key = await readFile(path.join(testPath, 'intName_key.pem'), { encoding: 'utf8' });
    res = await httpRequest('post', url + '/api/uploadKey', null, key, 'text/plain');
    assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
    await ew.EventWait();
    ew.EventReset();
    msg = JSON.parse(wsQueue.shift() as string);
    checkPacket(msg, 'intName_key', 1, 1, 0);
    checkItems(msg.added, [{ type: 4, id: 4 }]);
    checkItems(msg.updated, [{ type: 2, id:2 }]);
    return true;
}

async function getCertificateWithBadParameter(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?xx=bad');
    assert.equal(res.statusCode, 400, 'This should have failed');
    return true;
}

async function getCertificateWithNonexistentName(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?name=bad');
    assert.equal(res.statusCode, 404, 'This should have failed');
    return true;
}

async function getCertificateWithNonexistentId(): Promise<boolean> {
    res = await httpRequest('get', url + '/api/getCertificatePem?id=bad');
    assert.equal(res.statusCode, 404, 'This should have failed');
    return true;
}

async function bashDownloadAndSource(): Promise<boolean> {
    try {
        let scriptLoc = path.join(testPath, bashHelperScript);
        res = await httpRequest('get', url + '/api/test?os=linux');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await writeFile(scriptLoc, res.body);
        execSync(`${shells.bash.command} -c "source ${scriptLoc}"`);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashTestUrlEncode(): Promise<boolean> {
    // Assumes script has already been downloaded
    const test = '%2Amark~%21%40%23%24%25%5E%26%2A%28%29_-%2B%3D%2C.%3C%3E%2F%3F%3A%3B';
    let response = await runShellCommands(['urlencode "*mark~!@#$%^&*()_-+=,.<>/?:;"'], shells.bash);
    assert.equal(response[0], test, `urlencode created an invalid encoded string: returned ${response[0]} - should be ${test}`);
    return true;
}

async function bashGetServer(): Promise<boolean> {
    try {
        let response = await runShellCommands(['echo $CERTSERVER_HOST'], shells.bash);
        assert.equal(response[0], url, `Environment variable CERTSERVER_HOST is incorrect - returned ${response[0]} - should be ${url}`);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashGetIoTStats(): Promise<boolean> {
    try {
        let response = await runShellCommands([`getservicestatistics "${sasToken.SASToken}" ${sasToken.url}`], shells.bash);
        assert.match(response[0], /\{"connectedDeviceCount":\d*\}/);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashContactHubWithGarbageConnectionString(): Promise<boolean> {
    try {
        let response = await runShellCommands([`sasToken=$(generate_sas_token "garbageConnectionString") && getservicestatistics "$sasToken" ${sasToken.url} || echo Error: $sasToken`], shells.bash);
        assert.equal(response[0], 'Error: Connection string is invalid');
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashContactHubWithBadConnectionString(): Promise<boolean> {
    try {
        let badString = "HostName=CertTestHub1.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=qEpAdhXkKWw2uyGPWSft9RQ7kKnPKG1wFiGQ6IK1111="

        let response = await runShellCommands([`sasToken=$(generate_sas_token "${badString}") && getservicestatistics "$sasToken" ${sasToken.url}`], shells.bash)
        assert.match(response[0], /Unauthorized/);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashGenDevice(): Promise<boolean> {
    try {
        let response = await runShellCommands([`pushd ${testPath}`, `gendevice "${connectionString}" 4 serverTest`, 'popd'], shells.bash)
        assert.equal(response[2], 'Device serverTest created', `Device creation failed: ${response[1]}`);
        assert.equal(response[4], 'Certificate created', `Certificate creation failed: ${response[3]}`);
        assert.match(response[17], /‘serverTest_chain.pem’ saved/);
        assert.match(response[29], /‘serverTest_key.pem’ saved/);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function bashRemDevice(): Promise<boolean> {
    try {
        let response = await runShellCommands([`remdevice "${connectionString}" serverTest`], shells.bash);
        assert.equal(response[1], 'Key deleted', `Failed to delete key: ${response[1]}`);
        assert.equal(response[3], 'Certificate deleted', `Failed to delete certificate: ${response[3]}`);
        assert.equal(response[5], 'Device serverTest deleted', `Failed to delete device: ${response[5]}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        // await ew.EventWait();
        // ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function pwshDownloadAndSource(): Promise<boolean> {
    try {
        let scriptLoc = path.join(testPath, pwshHelperScript);
        res = await httpRequest('get', url + '/api/test?os=windows');
        assert.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        await writeFile(scriptLoc, res.body);
        execSync(`${shells.powershell.command} -c ". ${scriptLoc}"`);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function pwshGetServer(): Promise<boolean> {
    try {
        let response = await runShellCommands(['Write-Output(Get-ChildItem env:\\CERTSERVER_HOST).Value'], shells.powershell);
        assert.equal(response[1], url, `Environment variable CERTSERVER_HOST is incorrect - returned ${response[1]} - should be ${url}`);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function pwshGetIoTStats(): Promise<boolean> {
    try {
        let response = await runShellCommands([`Get-Server-Statistics "${connectionString}" | ConvertTo-Json`], shells.powershell);
        assert.match(response[3], /\"connectedDeviceCount\":\d*/);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function pwshGenDevice(): Promise<boolean> {
    try {
        let response = await runShellCommands([`Push-Location ${testPath}`, `New-Device "${connectionString}" 4 serverTest`, 'Pop-Location'], shells.powershell)
        assert.equal(response[3], 'Device serverTest created', `Device creation failed: ${response[3]}`);
        assert.equal(response[4], 'Certificate created', `Certificate creation failed: ${response[4]}`);
        assert.match(response[7], /serverTest_chain.pem written/);
        assert.match(response[9], /serverTest_key.pem written/);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function pwshRemDevice(): Promise<boolean> {
    try {
        let response = await runShellCommands([`Remove-Device "${connectionString}" serverTest`], shells.powershell);
        assert.equal(response[1], 'Certificate serverTest deleted', `Failed to delete certificate: ${response[1]}`);
        assert.equal(response[2], 'Key deleted', `Failed to delete key: ${response[2]}`);
        assert.equal(response[4], 'Device serverTest deleted', `Failed to delete device: ${response[4]}`);
        await ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift() as string);
        msg = JSON.parse(wsQueue.shift() as string);
        return true;
    }
    catch (e) {
        console.log(`Failed: ${e}`);
        return false;
    }
}

async function cleanUp(): Promise<boolean> {
    ws.close();
    webServer.kill('SIGTERM');
    await unlink(path.join(testPath, 'testconfig.yml'));
    await rm(testPath, { recursive: true, force: true });

    return true;
}

async function runTests() {
    console.log(`Running ${tests.length} test${tests.length == 1? '' : 's'}`);
    console.log(`LOG_SERVER_STDOUT: ${process.env.LOG_SERVER_STDOUT}`);
    console.log(`RUN_API_TESTS: ${process.env.RUN_API_TESTS}`);
    console.log(`RUN_IOTHUB_TESTS: ${process.env.RUN_IOTHUB_TESTS}`);
    console.log(`RUN_BASH_HELPER_TESTS: ${process.env.RUN_BASH_HELPER_TESTS}`);
    console.log(`RUN_POWERSHELL_HELPER_TESTS: ${process.env.RUN_POWERSHELL_HELPER_TESTS}`);
    let testSelection: TestType = 
        (process.env.RUN_API_TESTS == '1'? TestType.RunForAPITests : TestType.NoRun) |
        (process.env.RUN_BASH_HELPER_TESTS == '1' ? TestType.RunForBashTests : TestType.NoRun) |
        (process.env.RUN_POWERSHELL_HELPER_TESTS == '1' ? TestType.RunForPowerShellTests : TestType.NoRun);

    shells = getAvailableShells();
    let testAvailable: TestType = 
        TestType.RunForAPITests |
            (shells.bash.available? TestType.RunForBashTests : TestType.NoRun) |
            (shells.powershell.available? TestType.RunForPowerShellTests: TestType.NoRun);

    if ((testSelection & TestType.RunForBashTests) && (!(testAvailable & TestType.RunForBashTests))) {
        console.warn('Unable to run bash tests - bash is not available');
    }

    if ((testSelection & TestType.RunForPowerShellTests) && (!(testAvailable & TestType.RunForPowerShellTests))) {
        console.warn('Unable to run PowerShell tests - PowerShell is not available');
    }
    let runIoTHubTests = process.env.RUN_IOTHUB_TESTS == '1';

    if (runIoTHubTests && (shells.bash.available && (testSelection & TestType.RunForBashTests) || (shells.powershell.available && (testSelection & TestType.RunForPowerShellTests)))) {
        console.log('Extended tests for bash or powershell scripts require access to an IoT hub.');
        connectionString = await getResponse('If you wish to run those please enter a service connection string or enter to skip: ');
        try {
            sasToken = getSASToken(connectionString);
            let res: Response = await httpRequest('get', `${sasToken.url}/statistics/service?api-version=2020-05-31-preview`, { 'Authorization': sasToken.SASToken });
            if (res.statusCode != 200) {
                console.error(`SAS token did not work: ${res.body.Message}`);
                sasToken = null;
            }
        }
        catch (e)
        {
            console.error('SAS token is invalid - IoT hub tests skipped');
            sasToken = null;
        }
    }

    for (let test in tests) {
        // Don't run if the test type was not selected
        if (!(tests[test].runCondition & testSelection)) {
            console.log(`Test ${test}: ${tests[test].description} - Function skipped because test type was not selected`);
            tests[test].result = TestResult.TestSkippedNotSelected;
        }
        // Don't run if the environment is not available (bash or PowerShell)
        else if ((tests[test].runCondition & testAvailable) == 0) {
            console.log(`Test ${test}: ${tests[test].description} - Function skipped because test environment is not available`);
            tests[test].result = TestResult.TestSkippedNoEnvironment;
        }
        // Don't run if the test function is null
        else if (tests[test].testFunction == null) {
            console.log(`Test ${test}: ${tests[test].description} - Skipped due to function is a placeholder`);
            tests[test].result = TestResult.TestSkippedPlaceHolder;
        }
        else if (tests[test].runRequiresSASToken && (!runIoTHubTests || sasToken == null)) {
            if (!runIoTHubTests) {
                console.log(`Test ${test}: ${tests[test].description} - Skipped because IoT hub tests was not selected`);
                tests[test].result = TestResult.TestSkippedNotSelected;
            }
            else {
                console.log(`Test ${test}: ${tests[test].description} - Skipped due to missing or invalid SAS token`);
                tests[test].result = TestResult.TestSkippedMissingOrInvalidConnectionString
            }
        }
        else {
            let succeeded = tests.map((entry) => entry.result).reduce((previousValue, currentValue): TestResult => {
                return currentValue == TestResult.TestFailed? currentValue : previousValue;
            }, TestResult.TestSucceeded);
            // Don't run if there has been a failure and this test is not set to run on failure
            if (succeeded == TestResult.TestSucceeded || tests[test].runOnFailure == true) {
                console.log(`Test ${test}: ${tests[test].description}`);
                try {
                    tests[test].result = (await tests[test].testFunction())? TestResult.TestSucceeded : TestResult.TestFailed;
                    if (tests[test].result != TestResult.TestSucceeded) {
                        console.error(`Test ${test}: ${fgRed('failed')}`);
                    }
                    else {
                        console.log(`Test ${test}: ${fgGreen('succeeded')}`);
                    }
                }
                catch (err) {
                    console.error(`Error caught in test ${test} - ${err.message}`);
                    tests[test].result = TestResult.TestFailed;
                }
            }
            else {
                tests[test].result = TestResult.TestSkippedPreviousFailure;
                console.log(`Test ${test}: ${tests[test].description} - Skipped due to previous failure`);
            }
        }
    }

    let work;
    work = tests.filter((entry) => entry.result == TestResult.TestSkippedNoEnvironment);
    if (work.length > 0) console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to no available environment`);
    work = tests.filter((entry) => entry.result == TestResult.TestSkippedNotSelected);
    if (work.length > 0) console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to not selected`);
    work = tests.filter((entry) => entry.result == TestResult.TestSkippedPlaceHolder);
    if (work.length > 0) console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to the function is only a placeholder`);
    work = tests.filter((entry) => entry.result == TestResult.TestSkippedMissingOrInvalidConnectionString);
    if (work.length > 0) console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to missing or invalid connection string`);
    work = tests.filter((entry) => entry.result == TestResult.TestSkippedPreviousFailure);
    if (work.length > 0) console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to previous failure`);

    work = tests.map((entry, index) => { if (entry.result == TestResult.TestFailed) return index }).filter((entry) => entry != null);

    if (work.length > 0) {
        console.error(`The following test${work.length == 1? '' : 's'} failed:`);
        for (let test in work) {
            console.error(`${work[test]} - ${tests[work[test]].description}`);
        }
        console.error(`${work.length} test${work.length == 1? '' : 's'} failed`);
        process.exit(4);
    }
    else {
        console.log(fgGreen('All tests passed'));
    }
}

async function getResponse(question: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        try {
            const rl = readline.createInterface({ input, output });

            rl.question(question, (answer) => {
                resolve(answer);
                rl.close();
            });
        }
        catch (e) {
            console.log('Failed to get response');
            reject(e);
        }
    })
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

async function httpRequest(method: 'get' | 'post' | 'delete' | 'head', url: URL | string, headers: OutgoingHttpHeaders = null, body: string = null, contentType: string = 'application/json'): Promise<Response> {
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

        let options: http.RequestOptions = {
            method: method.toUpperCase(),
            hostname: urlObject.hostname,
            port: urlObject.port,
            path: urlObject.pathname,
            headers: {},
        };

        if (body) {
            options.headers = { 'Content-Length': Buffer.byteLength(body), 'Content-Type': contentType };
        }

        if (headers) {
            options.headers = { ...options.headers, ...headers };
        }

        let worker = urlObject.protocol == 'https:'? https : http;

        const clientRequest = worker.request(url, { method: method.toUpperCase(), headers: options.headers }, incomingMessage => {

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

async function runShellCommands(commands: string[], shellInfo: ShellInfo ): Promise<string[]> {
    const outputStart = '>>>>';
    const outputEnd = '<<<<';
    return new Promise<string[]>(async (resolve, reject) => {
        try {
            // Assumes script has already been downloaded
            const scriptWaiter: EventWaiter = new EventWaiter();
            const cmdStream = [
                `${shellInfo.sourceCmd} ${shellInfo.scriptLoc}\n`,
                `${shellInfo.consoleOutCmd}"${outputStart}"\n`,
            ]
            .concat(commands.map((cmd) => cmd + '\n'))
            .concat(
                [
                    `${shellInfo.consoleOutCmd}"${outputEnd}"\n`,
                ]
            );

            const input = Readable.from(cmdStream);
            const runner = spawn(shellInfo.command, { stdio: ["pipe", "pipe", "pipe"] });
            let response: string[] = [];
            let output: string = '';

            runner.stdout.on("data", (data) => {
                output += data.toString();
            });

            runner.stderr.on("data", (data) => {
               reject(data.toString());
            });

            runner.on("error", (err) => {
                reject(err);
            });

            runner.on("exit", (_code) => {
                try {
                    let lines: string[] = output.split('\n').map((line) => shellInfo.consolePostProcessor(line));
                    let startLine = lines.findIndex((line: string) => line == outputStart);
                    let endLine = lines.findIndex((line: string) => line == outputEnd);
                    if (startLine == -1) throw new Error('Unable to find start of relevant command output');
                    if (endLine == -1) throw new Error('Unable to find end of relevant command output');
                    response = lines.slice(startLine + 1, endLine);
                    scriptWaiter.EventSet();
                }
                catch (e) {
                    reject(e);
                }
            });

            input.pipe(runner.stdin);

            await scriptWaiter.EventWait();
            resolve(response);
        }
        catch (err) {
            reject(err);
        }
    });
}

const RESET = '\x1b[0m';
const FG_GREEN = '\x1b[32m';
const FG_RED = '\x1b[31m';

function fgGreen(s: string): string {
    return `${FG_GREEN}${s}${RESET}`;
}

function fgRed(s: string): string {
    return `${FG_RED}${s}${RESET}`;
}

function getAvailableShells(): Shells {
    let shells: Shells = { 
        bash: { 
            available: false, 
            command: null,
            scriptLoc: path.join(testPath, bashHelperScript),
            sourceCmd: 'source',
            consoleOutCmd: 'echo ',
            consolePostProcessor: (line: string): string => line,
        }, 
        powershell: { 
            available: false, 
            command: null,
            scriptLoc: path.join(testPath, pwshHelperScript),
            sourceCmd: '.',
            consoleOutCmd: 'Write-Host ',
            consolePostProcessor: (line: string): string => line.replace(/\x1b\[\?1./, ''),     // Remove pwsh color strings decorations
        } 
    }
    let output;
    if (process.platform == 'linux') {
        try {
            console.log('OS is Linux');
            output = execSync('which bash').toString().trim();
            shells.bash = { ...shells.bash, ...{ available: true, command: output } };
            console.log(`bash is available at ${shells.bash.command}`);
        }
        catch (e) {
            console.log(`bash not found - failed with ${e}`);
            shells.bash.available = false;
        }
        try {
            output = execSync('which pwsh').toString().trim();
            shells.powershell = { ...shells.powershell, ...{ available: true, command: output } };
            console.log(`PowerShell is available at ${shells.powershell.command}`);
        }
        catch (e) {
            console.log(`PowerShell not found - failed with ${e}`);
            shells.powershell.available = false;
        }
    }
    else if (process.platform.startsWith('win')) {
        console.log(`OS is ${process.platform}`);
        try {
            output = execSync('cmd /C "where pwsh"').toString().trim();
            shells.powershell = { ...shells.powershell, ...{ available: true, command: output } };
            console.log(`PowerShell is available at ${shells.powershell.command}`);
        }
        catch (e) {
            console.log(`PowerShell not found - failed with ${e}`);
            shells.powershell.available = false;
        }
        try {
            output = execSync('cmd /C "where bash"').toString().split('\n');
            shells.bash = { ...shells.bash, ...{ available: true, command: output[0] } };
            console.log(`bash is available at ${shells.bash.command}`);
        }
        catch (e) {
            console.log(`bash not found - failed with ${e}`);
            shells.bash.available = false;
        }
    }

    return shells;
}

runTests()
    // .then(() => wtfnode.dump());


