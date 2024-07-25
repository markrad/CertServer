"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const promises_1 = require("fs/promises");
const path_1 = __importDefault(require("path"));
const child_process_1 = require("child_process");
const node_assert_1 = __importDefault(require("node:assert"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const node_forge_1 = require("node-forge");
const stream_1 = require("stream");
const node_readline_1 = __importDefault(require("node:readline"));
const node_process_1 = require("node:process");
const ws_1 = __importDefault(require("ws"));
// import * as wtfnode from 'wtfnode';
const eventWaiter_1 = require("../utility/eventWaiter");
const OperationResultItem_1 = require("../webservertypes/OperationResultItem");
const generatesastoken_1 = require("../utility/generatesastoken");
const js_yaml_1 = require("js-yaml");
const CertTypes_1 = require("../webservertypes/CertTypes");
const testPath = path_1.default.join(__dirname, '../testdata');
const testConfig = path_1.default.join(testPath, 'testconfig.yml');
let useTls = false;
let useAuth = false;
let encryptKeys = false;
const host = 'localhost:9997';
let url = `http://${host}`;
let bearerToken = '';
let defaultUser = 'admin';
let defaultPassword = 'changeme';
let config = {
    certServer: {
        root: testPath,
        port: 9997,
        certificate: '',
        key: '',
        encryptKeys: false,
        useAuthentication: false,
        subject: {
            C: 'US',
            ST: 'TestState',
            L: 'TestCity',
            O: 'TestOrg',
            OU: 'TestUnit',
        }
    }
};
// const config: string = `certServer:
//   root: ${testPath}
//   port: 9997       
//   certificate: ''  
//   key: ''          
//   subject:         
//     C: US
//     ST: TestState
//     L: TestCity
//     O: TestOrg
//     OU: TestUnit`;
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
};
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
};
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
};
const bashHelperScript = 'bashHelper.sh';
const pwshHelperScript = 'pwshHelper.ps1';
var TestType;
(function (TestType) {
    TestType[TestType["NoRun"] = 0] = "NoRun";
    TestType[TestType["RunForAPITests"] = 1] = "RunForAPITests";
    TestType[TestType["RunForBashTests"] = 2] = "RunForBashTests";
    TestType[TestType["RunForPowerShellTests"] = 4] = "RunForPowerShellTests";
    TestType[TestType["RunForAllTests"] = 7] = "RunForAllTests";
})(TestType || (TestType = {}));
let shells;
let sasToken = null;
let connectionString;
var TestResult;
(function (TestResult) {
    TestResult[TestResult["TestNotYetRun"] = 0] = "TestNotYetRun";
    TestResult[TestResult["TestSucceeded"] = 1] = "TestSucceeded";
    TestResult[TestResult["TestFailed"] = 2] = "TestFailed";
    TestResult[TestResult["TestSkippedNotSelected"] = 3] = "TestSkippedNotSelected";
    TestResult[TestResult["TestSkippedNoEnvironment"] = 4] = "TestSkippedNoEnvironment";
    TestResult[TestResult["TestSkippedPlaceHolder"] = 5] = "TestSkippedPlaceHolder";
    TestResult[TestResult["TestSkippedPreviousFailure"] = 6] = "TestSkippedPreviousFailure";
    TestResult[TestResult["TestSkippedMissingOrInvalidConnectionString"] = 7] = "TestSkippedMissingOrInvalidConnectionString";
})(TestResult || (TestResult = {}));
// TODO: Add test to upload an encrypted key
let tests = [
    { description: 'Set up', runCondition: TestType.RunForAllTests, runOnFailure: true, testFunction: setup, result: TestResult.TestNotYetRun },
    { description: 'Create webserver', runCondition: TestType.RunForAllTests, runOnFailure: true, testFunction: createWebserver, result: TestResult.TestNotYetRun },
    { description: 'Connect WebSocket', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: connectWebSocket, result: TestResult.TestNotYetRun },
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
    // { description: 'Upload multifile', runCondition: TestType.RunForAllTests, runOnFailure: false, testFunction: uploadMultiFile, result: TestResult.TestNotYetRun },
    // bash script section
    { description: '[bash] Download and source bash helper script', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashDownloadAndSource, result: TestResult.TestNotYetRun },
    { description: '[bash] Ensure urlencode works', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashTestUrlEncode, result: TestResult.TestNotYetRun },
    { description: '[bash] Ensure environment variable points to server', runCondition: TestType.RunForBashTests, runOnFailure: false, testFunction: bashGetServer, result: TestResult.TestNotYetRun },
    { description: '[bash] Get service statistics', runCondition: TestType.RunForBashTests, runRequiresSASToken: true, runOnFailure: false, testFunction: bashGetIoTStats, result: TestResult.TestNotYetRun },
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
const types = ['root', 'intermediate', 'leaf', 'key'];
let webServer;
let ws;
let ew;
let res;
const wsQueue = []; // Used to pass data from WebSocket on message function to main thread
let msg;
let rski;
let iski;
let nextCertId = 0;
let nextKeyId = 0;
function setup() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            if (!fs_1.default.existsSync(testPath))
                yield (0, promises_1.mkdir)(`${testPath}/db`, { recursive: true });
            if (process.env.USE_TLS == '1') {
                if (!fs_1.default.existsSync(process.env.TLS_CERT))
                    console.log('Certificate not found - TLS will not be used');
                else if (!fs_1.default.existsSync(process.env.TLS_KEY))
                    console.log('Key not found - TLS will not be used');
                else {
                    config.certServer.certificate = process.env.TLS_CERT;
                    config.certServer.key = process.env.TLS_KEY;
                    useTls = true;
                    url = useTls ? `https://${host}` : `http://${host}`;
                }
            }
            if (process.env.USE_AUTH == '1') {
                config.certServer.useAuthentication = true;
                useAuth = true;
            }
            if (process.env.ENCRYPT_KEYS == '1') {
                config.certServer.encryptKeys = true;
                encryptKeys = true;
            }
            yield (0, promises_1.writeFile)(testConfig, (0, js_yaml_1.dump)(config));
            return true;
        }
        catch (err) {
            console.log(`Setup failed: ${err}`);
            return false;
        }
    });
}
function createWebserver() {
    return __awaiter(this, void 0, void 0, function* () {
        ew = new eventWaiter_1.EventWaiter();
        webServer = (0, child_process_1.spawn)('node', [path_1.default.join(__dirname, '../index.js'), testConfig]);
        webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
        webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
        webServer.stdout.on('data', (data) => { if (process.env.LOG_SERVER_STDOUT == "1")
            console.log(data.toString().trimEnd()); });
        yield new Promise((resolve) => setTimeout(() => resolve(), 2000));
        if (useAuth) {
            res = yield httpRequest('post', `${url}/api/login`, null, JSON.stringify({ userId: defaultUser, password: defaultPassword }));
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            (0, node_assert_1.default)(res.body.token, 'No token returned from server');
            bearerToken = res.body.token;
        }
        return true;
    });
}
function connectWebSocket() {
    return __awaiter(this, void 0, void 0, function* () {
        let ewLocal = new eventWaiter_1.EventWaiter();
        let err = null;
        let headers = {};
        if (useAuth)
            headers['Authorization'] = `Bearer ${bearerToken}`;
        ws = new ws_1.default(`${useTls ? 'wss' : 'ws'}://${host}`, { headers: headers });
        ws.on('error', (e) => {
            err = e;
            ewLocal.EventSet();
        });
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
        yield ewLocal.EventWait();
        if (err)
            console.error(`WebSocket connection failed: ${err}`);
        return err == null;
    });
}
function checkForEmptyDatabase() {
    return __awaiter(this, void 0, void 0, function* () {
        for (let dir in types) {
            res = yield httpRequest('get', `${url}/api/certList?type=${types[dir]}`);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            node_assert_1.default.equal(res.body.files.length, 0, `Failed: Expected zero entries for ${types[dir]} request`);
            console.log(`Passed: zero entries returned for ${types[dir]}`);
        }
        return true;
    });
}
function createCACertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        nextCertId++;
        nextKeyId++;
        res = yield httpRequest('post', `${url}/api/createCACert`, null, JSON.stringify(newCA));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'someName/someName_key', 2, 0, 0);
        checkItems(msg.added, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.root, id: nextCertId }), OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId })]);
        if (encryptKeys) {
            let key = yield (0, promises_1.readFile)(path_1.default.join(testPath, 'privatekeys/someName_key_1.pem'), { encoding: 'utf8' });
            (0, node_assert_1.default)(key.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----'), 'Key is not encrypted');
        }
        return true;
    });
}
function createIntermediateCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        nextCertId++;
        nextKeyId++;
        res = yield httpRequest('post', `${url}/api/createIntermediateCert`, null, JSON.stringify(newInt));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName/intName_key', 2, 0, 0);
        checkItems(msg.added, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId }), OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId })]);
        return true;
    });
}
function createLeafCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        nextCertId++;
        nextKeyId++;
        res = yield httpRequest('post', `${url}/api/createLeafCert`, null, JSON.stringify(newLeaf));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
        checkItems(msg.added, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.leaf, id: nextCertId }), OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId })]);
        return true;
    });
}
function addTagsToIntermediate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('post', `${url}/api/updateCertTag?id=2`, null, JSON.stringify({ tags: ['tag1', 'tag2'] }));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName', 0, 1, 0);
        checkItems(msg.updated, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId - 1 })]);
        return true;
    });
}
function getRootCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/certList?type=root`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'someName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'root', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 1, `File has incorrect id ${res.body.files[0].id}`);
        node_assert_1.default.equal(res.body.files[0].keyId, 1, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
        node_assert_1.default.deepEqual(res.body.files[0].tags, [], 'Tags are incorrect');
        return true;
    });
}
function getIntermediateCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/certList?type=intermediate`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'intName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'intermediate', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 2, `File has incorrect id ${res.body.files[0].id}`);
        node_assert_1.default.equal(res.body.files[0].keyId, 2, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
        node_assert_1.default.deepEqual(res.body.files[0].tags, ['tag1', 'tag2'], 'Tags are incorrect');
        return true;
    });
}
function getLeafCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/certList?type=leaf`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'leafName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'leaf', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 3, `File has incorrect id ${res.body.files[0].id}`);
        node_assert_1.default.equal(res.body.files[0].keyId, 3, `File has missing or incorrect key pair id ${res.body.files[0].keyId}`);
        return true;
    });
}
function getCertificateDetailsByID() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/certDetails?id=${nextCertId - 1}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        node_assert_1.default.equal(res.body.certType, 'intermediate', `Wrong certificate type ${res.body.certType} returned`);
        node_assert_1.default.equal(res.body.id, 2, `Wrong id ${res.body.id} returned`);
        node_assert_1.default.equal(res.body.keyId, 2, `Wrong key id ${res.body.keyId} returned`);
        node_assert_1.default.equal(res.body.name, 'intName', `Wrong name ${res.body.name} returned`);
        node_assert_1.default.deepEqual(res.body.tags, ['tag1', 'tag2'], 'Tags are incorrect');
        return true;
    });
}
function getKeyDetailsByID() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + `/keyDetails?id=${nextKeyId}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        return true;
    });
}
function checkDatabaseIsPopulated() {
    return __awaiter(this, void 0, void 0, function* () {
        for (let dir in types) {
            console.log(`get populated ${types[dir]} list`);
            res = yield httpRequest('get', `${url}/certList?type=${types[dir]}`);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            if (dir != '3') {
                node_assert_1.default.equal(res.body.files.length, 1, `Failed: Expected one entry for ${types[dir]} request`);
                console.log(`Passed: one entry returned for ${types[dir]}`);
            }
            else {
                node_assert_1.default.equal(res.body.files.length, 3, `Failed: Expected three entries for ${types[dir]} request`);
                console.log(`Passed: three entries returned for ${types[dir]}`);
            }
        }
        return true;
    });
}
function getKeyList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/keyList`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 3, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        let names = [['intName_key', 2], ['leafName_key', 3], ['someName_key', 1]];
        for (let i = 0; i < names.length; i++) {
            node_assert_1.default.equal(res.body.files[i].name, names[i][0], `File has incorrect name ${res.body.files[i].name}`);
            node_assert_1.default.equal(res.body.files[i].type, 'key', `File has incorrect type ${res.body.files[i].type}`);
            node_assert_1.default.equal(res.body.files[i].id, names[i][1], `File has incorrect id ${res.body.files[i].id}`);
        }
        return true;
    });
}
function getRootCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/getCertificatePem?id=${nextCertId - 2}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        let filename = res.headers['content-disposition'].split('=')[1];
        filename = filename.slice(1, filename.length - 1);
        node_assert_1.default.equal('someName.pem', filename);
        yield (0, promises_1.writeFile)(path_1.default.join(testPath, filename), res.body);
        let rootCert = node_forge_1.pki.certificateFromPem(res.body);
        rski = rootCert.getExtension('subjectKeyIdentifier');
        return true;
    });
}
function getIntermediateCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/getCertificatePem?id=${nextCertId - 1}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        let filename = res.headers['content-disposition'].split('=')[1];
        filename = filename.slice(1, filename.length - 1);
        node_assert_1.default.equal('intName.pem', filename);
        yield (0, promises_1.writeFile)(path_1.default.join(testPath, filename), res.body);
        let intermediateCert = node_forge_1.pki.certificateFromPem(res.body);
        iski = intermediateCert.getExtension('subjectKeyIdentifier');
        let iaki = intermediateCert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(rski.value.slice(1), iaki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        return true;
    });
}
function getLeafCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/getCertificatePem?id=${nextCertId}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        let filename = res.headers['content-disposition'].split('=')[1];
        filename = filename.slice(1, filename.length - 1);
        node_assert_1.default.equal('leafName.pem', filename);
        yield (0, promises_1.writeFile)(path_1.default.join(testPath, filename), res.body);
        let leafCert = node_forge_1.pki.certificateFromPem(res.body);
        let laki = leafCert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(iski.value.slice(1), laki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        let san = leafCert.getExtension('subjectAltName');
        node_assert_1.default.notEqual(san, null, 'Failed to get the subject alternate names');
        node_assert_1.default.equal(san.altNames.length, 3, 'Incorrect number of alt names on leaf');
        node_assert_1.default.deepEqual(san.altNames, [{ type: 2, value: 'leafName' }, { type: 2, value: 'leafy.com' }, { type: 7, value: "7777", ip: '55.55.55.55' }], 'Alt names do not match expected list');
        return true;
    });
}
function getLeafChainFile() {
    return __awaiter(this, void 0, void 0, function* () {
        let certHeader = '-----BEGIN CERTIFICATE-----';
        res = yield httpRequest('get', `${url}/api/chainDownload?id=${nextCertId}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        let filename = res.headers['content-disposition'].split('=')[1];
        filename = filename.slice(1, filename.length - 1);
        node_assert_1.default.equal('leafName_chain.pem', filename, 'The content-disposition header was incorrect');
        node_assert_1.default.equal(res.body.split(certHeader).length, 4, `Incorrect number of certificates returned in chain: ${res.body.split(certHeader).length}`);
        return true;
    });
}
function getKeyFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', `${url}/api/getKeyPem?id=${nextKeyId - 1}`);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        (0, node_assert_1.default)(res.body.startsWith('-----BEGIN RSA PRIVATE KEY-----'), 'Key is not an RSA private key');
        yield (0, promises_1.writeFile)(path_1.default.join(testPath, 'intName_key.pem'), res.body);
        return true;
    });
}
function deleteRootCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('delete', url + '/api/deleteCert?name=someName');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, '', 0, 2, 1);
        checkItems(msg.updated, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId - 2 }), OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId - 1 })]);
        checkItems(msg.deleted, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.root, id: nextCertId - 2 })]);
        res = yield httpRequest('get', url + '/certDetails?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        node_assert_1.default.equal(res.body.signerId, null, 'Signed certificate still references nonexistent parent');
        return true;
    });
}
function uploadRootCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        nextCertId++;
        let cert = yield (0, promises_1.readFile)(path_1.default.join(testPath, 'someName.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', url + '/api/uploadCert', null, cert, 'text/plain');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'multiple', 1, 2, 0);
        checkItems(msg.added, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.root, id: nextCertId })]);
        checkItems(msg.updated, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId - 2 }), OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId - 2 })]);
        res = yield httpRequest('get', url + '/certDetails?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        node_assert_1.default.equal(res.body.signerId, 4, 'Signed certificate does not reference uploaded parent');
        console.log('passed');
        return true;
    });
}
function deleteIntermediateKey() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('delete', url + '/api/deleteKey?name=intName_key');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, '', 0, 1, 1);
        checkItems(msg.updated, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId - 2 })]);
        checkItems(msg.deleted, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId - 1 })]);
        return true;
    });
}
function uploadIntermediateKey() {
    return __awaiter(this, void 0, void 0, function* () {
        nextKeyId++;
        let key = yield (0, promises_1.readFile)(path_1.default.join(testPath, 'intName_key.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', `${url}/api/uploadKey`, null, key, 'text/plain');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'multiple', 1, 1, 0);
        checkItems(msg.added, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.key, id: nextKeyId })]);
        checkItems(msg.updated, [OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.intermediate, id: nextCertId - 2 })]);
        return true;
    });
}
function getCertificateWithBadParameter() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?xx=bad');
        node_assert_1.default.equal(res.statusCode, 400, 'This should have failed');
        return true;
    });
}
function getCertificateWithNonexistentName() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?name=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        return true;
    });
}
function getCertificateWithNonexistentId() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        return true;
    });
}
function bashDownloadAndSource() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let scriptLoc = path_1.default.join(testPath, bashHelperScript);
            res = yield httpRequest('get', `${url}/api/helper?os=linux`);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            yield (0, promises_1.writeFile)(scriptLoc, res.body);
            (0, child_process_1.execSync)(`${shells.bash.command} -c "source ${scriptLoc}"`);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashTestUrlEncode() {
    return __awaiter(this, void 0, void 0, function* () {
        // Assumes script has already been downloaded
        const test = '%2Amark~%21%40%23%24%25%5E%26%2A%28%29_-%2B%3D%2C.%3C%3E%2F%3F%3A%3B';
        let response = yield runShellCommands(['urlencode "*mark~!@#$%^&*()_-+=,.<>/?:;"'], shells.bash);
        node_assert_1.default.equal(response[0], test, `urlencode created an invalid encoded string: returned ${response[0]} - should be ${test}`);
        return true;
    });
}
function bashGetServer() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands(['echo $CERTSERVER_HOST'], shells.bash);
            node_assert_1.default.equal(response[0], url, `Environment variable CERTSERVER_HOST is incorrect - returned ${response[0]} - should be ${url}`);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashGetIoTStats() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`getservicestatistics "${sasToken.SASToken}" ${sasToken.url}`], shells.bash);
            node_assert_1.default.match(response[0], /\{"connectedDeviceCount":\d*\}/);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashContactHubWithGarbageConnectionString() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`sasToken=$(generate_sas_token "garbageConnectionString") && getservicestatistics "$sasToken" ${sasToken.url} || echo Error: $sasToken`], shells.bash);
            node_assert_1.default.equal(response[0], 'Error: Connection string is invalid');
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashContactHubWithBadConnectionString() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let badString = "HostName=CertTestHub1.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=qEpAdhXkKWw2uyGPWSft9RQ7kKnPKG1wFiGQ6IK1111=";
            let response = yield runShellCommands([`sasToken=$(generate_sas_token "${badString}") && getservicestatistics "$sasToken" ${sasToken.url}`], shells.bash);
            node_assert_1.default.match(response[0], /Unauthorized/);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashGenDevice() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`pushd ${testPath}`, `gendevice "${connectionString}" ${nextCertId - 3} serverTest`, 'popd'], shells.bash);
            node_assert_1.default.equal(response[2], 'Device serverTest created', `Device creation failed: ${response[1]}`);
            node_assert_1.default.equal(response[4], 'Certificate created', `Certificate creation failed: ${response[3]}`);
            node_assert_1.default.match(response[17], /‘serverTest_chain.pem’ saved/);
            node_assert_1.default.match(response[29], /‘serverTest_key.pem’ saved/);
            yield ew.EventWait();
            ew.EventReset();
            msg = JSON.parse(wsQueue.shift());
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function bashRemDevice() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`remdevice "${connectionString}" serverTest`], shells.bash);
            node_assert_1.default.equal(response[1], 'Key deleted', `Failed to delete key: ${response[1]}`);
            node_assert_1.default.equal(response[3], 'Certificate deleted', `Failed to delete certificate: ${response[3]}`);
            node_assert_1.default.equal(response[5], 'Device serverTest deleted', `Failed to delete device: ${response[5]}`);
            yield ew.EventWait();
            ew.EventReset();
            msg = JSON.parse(wsQueue.shift());
            // await ew.EventWait();
            // ew.EventReset();
            msg = JSON.parse(wsQueue.shift());
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function pwshDownloadAndSource() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let scriptLoc = path_1.default.join(testPath, pwshHelperScript);
            res = yield httpRequest('get', url + '/api/helper?os=windows');
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            yield (0, promises_1.writeFile)(scriptLoc, res.body);
            (0, child_process_1.execSync)(`${shells.powershell.command} -c ". ${scriptLoc}"`);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function pwshGetServer() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands(['Write-Output(Get-ChildItem env:\\CERTSERVER_HOST).Value'], shells.powershell);
            node_assert_1.default.equal(response[1], url, `Environment variable CERTSERVER_HOST is incorrect - returned ${response[1]} - should be ${url}`);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function pwshGetIoTStats() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`Get-Server-Statistics "${connectionString}" | ConvertTo-Json`], shells.powershell);
            node_assert_1.default.match(response[3], /\"connectedDeviceCount\":\d*/);
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function pwshGenDevice() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`Push-Location ${testPath}`, `New-Device "${connectionString}" ${nextCertId - 3} serverTest`, 'Pop-Location'], shells.powershell);
            node_assert_1.default.equal(response[3], 'Device serverTest created', `Device creation failed: ${response[3]}`);
            node_assert_1.default.equal(response[4], 'Certificate created', `Certificate creation failed: ${response[4]}`);
            node_assert_1.default.match(response[7], /serverTest_chain.pem written/);
            node_assert_1.default.match(response[9], /serverTest_key.pem written/);
            yield ew.EventWait();
            ew.EventReset();
            msg = JSON.parse(wsQueue.shift());
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function pwshRemDevice() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            let response = yield runShellCommands([`Remove-Device "${connectionString}" serverTest`], shells.powershell);
            node_assert_1.default.equal(response[1], 'Certificate serverTest deleted', `Failed to delete certificate: ${response[1]}`);
            node_assert_1.default.equal(response[2], 'Key deleted', `Failed to delete key: ${response[2]}`);
            node_assert_1.default.equal(response[4], 'Device serverTest deleted', `Failed to delete device: ${response[4]}`);
            yield ew.EventWait();
            ew.EventReset();
            msg = JSON.parse(wsQueue.shift());
            msg = JSON.parse(wsQueue.shift());
            return true;
        }
        catch (e) {
            console.log(`Failed: ${e}`);
            return false;
        }
    });
}
function cleanUp() {
    return __awaiter(this, void 0, void 0, function* () {
        if (ws)
            ws.close();
        webServer.kill('SIGTERM');
        yield (0, promises_1.unlink)(path_1.default.join(testPath, 'testconfig.yml'));
        yield (0, promises_1.rm)(testPath, { recursive: true, force: true });
        return true;
    });
}
function runTests() {
    var _a, _b, _c, _d;
    return __awaiter(this, void 0, void 0, function* () {
        let onoff = (value) => Number(value) ? 'on' : 'off';
        console.log(`Running ${tests.length} test${tests.length == 1 ? '' : 's'}`);
        console.log(`LOG_SERVER_STDOUT: ${onoff(process.env.LOG_SERVER_STDOUT)}`);
        console.log(`RUN_API_TESTS: ${onoff(process.env.RUN_API_TESTS)}`);
        console.log(`RUN_IOTHUB_TESTS: ${onoff(process.env.RUN_IOTHUB_TESTS)}`);
        console.log(`RUN_BASH_HELPER_TESTS: ${onoff(process.env.RUN_BASH_HELPER_TESTS)}`);
        console.log(`RUN_POWERSHELL_HELPER_TESTS: ${onoff(process.env.RUN_POWERSHELL_HELPER_TESTS)}`);
        console.log(`USE_TLS: ${onoff(process.env.USE_TLS)}`);
        console.log(`TLS_CERT: ${(_a = process.env.TLS_CERT) !== null && _a !== void 0 ? _a : 'None'}`);
        console.log(`TLS_KEY: ${(_b = process.env.TLS_KEY) !== null && _b !== void 0 ? _b : 'None'}`);
        console.log(`USE_AUTH: ${onoff(process.env.USE_AUTH)}`);
        console.log(`AUTH_USERID: ${(_c = process.env.AUTH_USERID) !== null && _c !== void 0 ? _c : 'None'}`);
        console.log(`AUTH_PASSWORD: ${(_d = process.env.AUTH_PASSWORD) !== null && _d !== void 0 ? _d : 'None'}`);
        console.log(`ENCRYPT_KEYS: ${onoff(process.env.ENCRYPT_KEYS)}`);
        let testSelection = (process.env.RUN_API_TESTS == '1' ? TestType.RunForAPITests : TestType.NoRun) |
            (process.env.RUN_BASH_HELPER_TESTS == '1' ? TestType.RunForBashTests : TestType.NoRun) |
            (process.env.RUN_POWERSHELL_HELPER_TESTS == '1' ? TestType.RunForPowerShellTests : TestType.NoRun);
        shells = getAvailableShells();
        let testAvailable = TestType.RunForAPITests |
            (shells.bash.available ? TestType.RunForBashTests : TestType.NoRun) |
            (shells.powershell.available ? TestType.RunForPowerShellTests : TestType.NoRun);
        if ((testSelection & TestType.RunForBashTests) && (!(testAvailable & TestType.RunForBashTests))) {
            console.warn('Unable to run bash tests - bash is not available');
        }
        if ((testSelection & TestType.RunForPowerShellTests) && (!(testAvailable & TestType.RunForPowerShellTests))) {
            console.warn('Unable to run PowerShell tests - PowerShell is not available');
        }
        let runIoTHubTests = process.env.RUN_IOTHUB_TESTS == '1';
        if (runIoTHubTests && (shells.bash.available && (testSelection & TestType.RunForBashTests) || (shells.powershell.available && (testSelection & TestType.RunForPowerShellTests)))) {
            console.log('Extended tests for bash or powershell scripts require access to an IoT hub.');
            connectionString = yield getResponse('If you wish to run those please enter a service connection string or enter to skip: ');
            try {
                sasToken = (0, generatesastoken_1.getSASToken)(connectionString);
                let res = yield httpRequest('get', `${sasToken.url}/statistics/service?api-version=2020-05-31-preview`, { 'Authorization': sasToken.SASToken });
                if (res.statusCode != 200) {
                    console.error(`SAS token did not work: ${res.body.Message}`);
                    sasToken = null;
                }
            }
            catch (e) {
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
                    tests[test].result = TestResult.TestSkippedMissingOrInvalidConnectionString;
                }
            }
            else {
                let succeeded = tests.map((entry) => entry.result).reduce((previousValue, currentValue) => {
                    return currentValue == TestResult.TestFailed ? currentValue : previousValue;
                }, TestResult.TestSucceeded);
                // Don't run if there has been a failure and this test is not set to run on failure
                if (succeeded == TestResult.TestSucceeded || tests[test].runOnFailure == true) {
                    console.log(`Test ${test}: ${fgGreen(tests[test].description)}`);
                    try {
                        tests[test].result = (yield tests[test].testFunction()) ? TestResult.TestSucceeded : TestResult.TestFailed;
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
        if (work.length > 0)
            console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to no available environment`);
        work = tests.filter((entry) => entry.result == TestResult.TestSkippedNotSelected);
        if (work.length > 0)
            console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to not selected`);
        work = tests.filter((entry) => entry.result == TestResult.TestSkippedPlaceHolder);
        if (work.length > 0)
            console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to the function is only a placeholder`);
        work = tests.filter((entry) => entry.result == TestResult.TestSkippedMissingOrInvalidConnectionString);
        if (work.length > 0)
            console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to missing or invalid connection string`);
        work = tests.filter((entry) => entry.result == TestResult.TestSkippedPreviousFailure);
        if (work.length > 0)
            console.log(`${work.length} test${work.length == 1 ? '' : 's'} skipped due to previous failure`);
        work = tests.map((entry, index) => { if (entry.result == TestResult.TestFailed)
            return index; }).filter((entry) => entry != null);
        if (work.length > 0) {
            console.error(`The following test${work.length == 1 ? '' : 's'} failed:`);
            for (let test in work) {
                console.error(`${work[test]} - ${tests[work[test]].description}`);
            }
            console.error(`${work.length} test${work.length == 1 ? '' : 's'} failed`);
            process.exit(4);
        }
        else {
            console.log(fgGreen('All tests passed'));
        }
    });
}
function getResponse(question) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            try {
                const rl = node_readline_1.default.createInterface({ input: node_process_1.stdin, output: node_process_1.stdout });
                rl.question(question, (answer) => {
                    resolve(answer);
                    rl.close();
                });
            }
            catch (e) {
                console.log('Failed to get response');
                reject(e);
            }
        });
    });
}
function checkPacket(packet, name, added, updated, deleted) {
    node_assert_1.default.equal(packet.name, name, `Failed: Incorrect certificate/key names - expected ${name}, received ${packet.name}`);
    node_assert_1.default.equal(packet.added.length, added, `Incorrect added length - expected ${added}, received ${packet.added.length}`);
    node_assert_1.default.equal(packet.updated.length, updated, `Incorrect updated length - expected ${updated}, received ${packet.updated.length}`);
    node_assert_1.default.equal(packet.deleted.length, deleted, `Incorrect deleted length - expected ${deleted}, received ${packet.deleted.length}`);
}
function checkItems(items, test) {
    node_assert_1.default.equal(items.length, test.length, `Entry counts do not match - ${test.length}, received ${items.length}`);
    for (let i = 0; i < items.length; i++) {
        node_assert_1.default.equal(OperationResultItem_1.OperationResultItem.makeResult(items[i]).isEqual(test[i]), true);
    }
}
function httpRequest(method, url, headers = null, body = null, contentType = 'application/json') {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
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
            if (useAuth && bearerToken) {
                options.headers = Object.assign(Object.assign({}, options.headers), { 'Authorization': `Bearer ${bearerToken}` });
            }
            if (headers) {
                options.headers = Object.assign(Object.assign({}, options.headers), headers);
            }
            let worker = urlObject.protocol == 'https:' ? https_1.default : http_1.default;
            const clientRequest = worker.request(url, { method: method.toUpperCase(), headers: options.headers }, incomingMessage => {
                // Response object.
                let response = {
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
                        }
                        catch (error) {
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
    });
}
function runShellCommands(commands, shellInfo) {
    return __awaiter(this, void 0, void 0, function* () {
        const outputStart = '>>>>';
        const outputEnd = '<<<<';
        return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            try {
                // Assumes script has already been downloaded
                const scriptWaiter = new eventWaiter_1.EventWaiter();
                const cmdStream = [
                    `${shellInfo.sourceCmd} ${shellInfo.scriptLoc}\n`,
                    `${shellInfo.consoleOutCmd}"${outputStart}"\n`,
                ]
                    .concat(commands.map((cmd) => cmd + '\n'))
                    .concat([
                    `${shellInfo.consoleOutCmd}"${outputEnd}"\n`,
                ]);
                const input = stream_1.Readable.from(cmdStream);
                const runner = (0, child_process_1.spawn)(shellInfo.command, { stdio: ["pipe", "pipe", "pipe"] });
                let response = [];
                let output = '';
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
                        let lines = output.split('\n').map((line) => shellInfo.consolePostProcessor(line));
                        let startLine = lines.findIndex((line) => line == outputStart);
                        let endLine = lines.findIndex((line) => line == outputEnd);
                        if (startLine == -1)
                            throw new Error('Unable to find start of relevant command output');
                        if (endLine == -1)
                            throw new Error('Unable to find end of relevant command output');
                        response = lines.slice(startLine + 1, endLine);
                        scriptWaiter.EventSet();
                    }
                    catch (e) {
                        reject(e);
                    }
                });
                input.pipe(runner.stdin);
                yield scriptWaiter.EventWait();
                resolve(response);
            }
            catch (err) {
                reject(err);
            }
        }));
    });
}
const RESET = '\x1b[0m';
const FG_GREEN = '\x1b[32m';
const FG_RED = '\x1b[31m';
function fgGreen(s) {
    return `${FG_GREEN}${s}${RESET}`;
}
function fgRed(s) {
    return `${FG_RED}${s}${RESET}`;
}
function getAvailableShells() {
    let shells = {
        bash: {
            available: false,
            command: null,
            scriptLoc: path_1.default.join(testPath, bashHelperScript),
            sourceCmd: 'source',
            consoleOutCmd: 'echo ',
            consolePostProcessor: (line) => line,
        },
        powershell: {
            available: false,
            command: null,
            scriptLoc: path_1.default.join(testPath, pwshHelperScript),
            sourceCmd: '.',
            consoleOutCmd: 'Write-Host ',
            consolePostProcessor: (line) => line.replace(/\x1b\[\?1./, ''), // Remove pwsh color strings decorations
        }
    };
    let output;
    if (process.platform == 'linux') {
        try {
            console.log('OS is Linux');
            output = (0, child_process_1.execSync)('which bash').toString().trim();
            shells.bash = Object.assign(Object.assign({}, shells.bash), { available: true, command: output });
            console.log(`bash is available at ${shells.bash.command}`);
        }
        catch (e) {
            console.log(`bash not found - failed with ${e}`);
            shells.bash.available = false;
        }
        try {
            output = (0, child_process_1.execSync)('which pwsh').toString().trim();
            shells.powershell = Object.assign(Object.assign({}, shells.powershell), { available: true, command: output });
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
            output = (0, child_process_1.execSync)('cmd /C "where pwsh"').toString().trim();
            shells.powershell = Object.assign(Object.assign({}, shells.powershell), { available: true, command: output });
            console.log(`PowerShell is available at ${shells.powershell.command}`);
        }
        catch (e) {
            console.log(`PowerShell not found - failed with ${e}`);
            shells.powershell.available = false;
        }
        try {
            output = (0, child_process_1.execSync)('cmd /C "where bash"').toString().split('\n');
            shells.bash = Object.assign(Object.assign({}, shells.bash), { available: true, command: output[0] });
            console.log(`bash is available at ${shells.bash.command}`);
        }
        catch (e) {
            console.log(`bash not found - failed with ${e}`);
            shells.bash.available = false;
        }
    }
    return shells;
}
runTests();
// .then(() => wtfnode.dump());
//# sourceMappingURL=tests.js.map