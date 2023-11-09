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
const path_1 = __importDefault(require("path"));
const child_process_1 = require("child_process");
const node_assert_1 = __importDefault(require("node:assert"));
const http_1 = __importDefault(require("http"));
const node_forge_1 = require("node-forge");
const ws_1 = __importDefault(require("ws"));
const eventWaiter_1 = require("../utility/eventWaiter");
const testPath = path_1.default.join(__dirname, '../testdata');
const testConfig = path_1.default.join(testPath, 'testconfig.yml');
const url = 'http://localhost:9997';
const config = `certServer:
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
};
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
};
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
};
let tests = [
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
const types = ['root', 'intermediate', 'leaf', 'key'];
let webServer;
let ws;
let ew;
let res;
const wsQueue = []; // Used to pass data from WebSocket on message function to main thread
let msg;
let rski;
let iski;
function setup() {
    return __awaiter(this, void 0, void 0, function* () {
        if (!fs_1.default.existsSync(testPath))
            fs_1.default.mkdirSync(testPath);
        fs_1.default.writeFileSync(testConfig, config);
        return true;
    });
}
function createWebserver() {
    return __awaiter(this, void 0, void 0, function* () {
        ew = new eventWaiter_1.EventWaiter();
        webServer = (0, child_process_1.spawn)('node', [path_1.default.join(__dirname, '../index.js'), testConfig]);
        webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
        webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
        webServer.stdout.on('data', (data) => console.log(data.toString()));
        yield new Promise((resolve) => setTimeout(() => resolve(), 2000));
        return true;
    });
}
function connectWebSocket() {
    return __awaiter(this, void 0, void 0, function* () {
        let ewLocal = new eventWaiter_1.EventWaiter();
        ws = new ws_1.default('ws://localhost:9997');
        ws.on('error', (err) => { throw err; });
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
        return true;
    });
}
function checkForEmptyDatabase() {
    return __awaiter(this, void 0, void 0, function* () {
        for (let dir in types) {
            res = yield httpRequest('get', url + '/api/certList?type=' + types[dir]);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            node_assert_1.default.equal(res.body.files.length, 0, `Failed: Expected zero entries for ${types[dir]} request`);
            console.log(`Passed: zero entries returned for ${types[dir]}`);
        }
        return true;
    });
}
function createCACertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('post', url + '/api/createCACert', JSON.stringify(newCA));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'someName/someName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 1, id: 1 }, { type: 4, id: 1 }]);
        console.log('passed');
        return true;
    });
}
function createIntermediateCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('post', url + '/api/createIntermediateCert', JSON.stringify(newInt));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName/intName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 2, id: 2 }, { type: 4, id: 2 }]);
        console.log('passed');
        return true;
    });
}
function createLeafCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('post', url + '/api/createLeafCert', JSON.stringify(newLeaf));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 3, id: 3 }, { type: 4, id: 3 }]);
        console.log('passed');
        return true;
    });
}
function addTagsToIntermediate() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('post', url + '/api/updateCertTag?id=2', JSON.stringify({ tags: 'tag1 ; tag2' }));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName', 0, 1, 0);
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        console.log('passed');
        return true;
    });
}
function getRootCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/certList?type=root');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'someName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'root', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 1, `File has incorrect id ${res.body.files[0].id}`);
        node_assert_1.default.deepEqual(res.body.files[0].tags, [], 'Tags are incorrect');
        // let rootId = res.body.files[0].id;
        console.log('passed');
        return true;
    });
}
function getIntermediateCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/certList?type=intermediate');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'intName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'intermediate', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 2, `File has incorrect id ${res.body.files[0].id}`);
        node_assert_1.default.deepEqual(res.body.files[0].tags, ['tag1', 'tag2'], 'Tags are incorrect');
        // let intId = res.body.files[0].id;
        console.log('passed');
        return true;
    });
}
function getLeafCertificateList() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/certList?type=leaf');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'leafName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'leaf', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 3, `File has incorrect id ${res.body.files[0].id}`);
        // let leafId = res.body.files[0].id;
        console.log('passed');
        return true;
    });
}
function getCertificateDetailsByID() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/certDetails?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        node_assert_1.default.equal(res.body.certType, 'intermediate', `Wrong certificate type ${res.body.certType} returned`);
        node_assert_1.default.equal(res.body.id, 2, `Wrong id ${res.body.id} returned`);
        node_assert_1.default.equal(res.body.keyId, 2, `Wrong key id ${res.body.keyId} returned`);
        node_assert_1.default.equal(res.body.name, 'intName', `Wrong name ${res.body.name} returned`);
        node_assert_1.default.deepEqual(res.body.tags, ['tag1', 'tag2'], 'Tags are incorrect');
        console.log('passed');
        return true;
    });
}
function getKeyDetailsByID() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/keyDetails?id=3');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        console.log('passed');
        return true;
    });
}
function checkDatabaseIsPopulated() {
    return __awaiter(this, void 0, void 0, function* () {
        for (let dir in types) {
            console.log(`get populated ${types[dir]} list`);
            res = yield httpRequest('get', url + '/certList?type=' + types[dir]);
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
        res = yield httpRequest('get', url + '/api/keyList');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 3, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        let names = [['intName_key', 2], ['leafName_key', 3], ['someName_key', 1]];
        for (let i = 0; i < names.length; i++) {
            node_assert_1.default.equal(res.body.files[i].name, names[i][0], `File has incorrect name ${res.body.files[i].name}`);
            node_assert_1.default.equal(res.body.files[i].type, 'key', `File has incorrect type ${res.body.files[i].type}`);
            node_assert_1.default.equal(res.body.files[i].id, names[i][1], `File has incorrect id ${res.body.files[i].id}`);
        }
        console.log('passed');
        return true;
    });
}
function getRootCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=' + '1');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'someName.pem'), res.body);
        let rootCert = node_forge_1.pki.certificateFromPem(res.body);
        rski = rootCert.getExtension('subjectKeyIdentifier');
        console.log(JSON.stringify(rski, null, 4));
        console.log('passed');
        return true;
    });
}
function getIntermediateCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=' + '2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'intName.pem'), res.body);
        let intermediateCert = node_forge_1.pki.certificateFromPem(res.body);
        iski = intermediateCert.getExtension('subjectKeyIdentifier');
        let iaki = intermediateCert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(rski.value.slice(1), iaki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');
        return true;
    });
}
function getLeafCertificateFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=' + '3');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'leafName.pem'), res.body);
        let leafCert = node_forge_1.pki.certificateFromPem(res.body);
        let laki = leafCert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(iski.value.slice(1), laki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');
        return true;
    });
}
function getKeyFile() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getKeyPem?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'intName_key.pem'), res.body);
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
        checkItems(msg.updated, [{ type: 4, id: 1 }, { type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 1, id: 1 }]);
        res = yield httpRequest('get', url + '/certDetails?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        node_assert_1.default.equal(res.body.signerId, null, 'Signed certificate still references nonexistent parent');
        console.log('passed');
        return true;
    });
}
function uploadRootCertificate() {
    return __awaiter(this, void 0, void 0, function* () {
        let cert = fs_1.default.readFileSync(path_1.default.join(testPath, 'someName.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', url + '/api/uploadCert', cert, 'text/plain');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode} ${res.body.error}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'someName', 1, 2, 0);
        checkItems(msg.added, [{ type: 1, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id: 2 }, { type: 4, id: 1 }]);
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
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 4, id: 2 }]);
        // console.log(msg);
        console.log('passed');
        return true;
    });
}
function uploadIntermediateKey() {
    return __awaiter(this, void 0, void 0, function* () {
        let key = fs_1.default.readFileSync(path_1.default.join(testPath, 'intName_key.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', url + '/api/uploadKey', key, 'text/plain');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName_key', 1, 1, 0);
        checkItems(msg.added, [{ type: 4, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        console.log('passed');
        return true;
    });
}
function getCertificateWithBadParameter() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?xx=bad');
        node_assert_1.default.equal(res.statusCode, 400, 'This should have failed');
        console.log('passed');
        return true;
    });
}
function getCertificateWithNonexistentName() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?name=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');
        return true;
    });
}
function getCertificateWithNonexistentId() {
    return __awaiter(this, void 0, void 0, function* () {
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');
        return true;
    });
}
function cleanUp() {
    return __awaiter(this, void 0, void 0, function* () {
        ws.close();
        webServer.kill('SIGTERM');
        fs_1.default.unlinkSync(path_1.default.join(testPath, 'testconfig.yml'));
        fs_1.default.rmSync(testPath, { recursive: true, force: true });
        return true;
    });
}
runTests();
function runTests() {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(`Running ${tests.length} test${tests.length == 1 ? '' : 's'}`);
        for (let test in tests) {
            let succeeded = tests.map((entry) => entry.result).reduce((previousValue, currentValue) => {
                return currentValue == false ? currentValue : previousValue;
            }, true);
            let run = (succeeded == true || tests[test].runOnFailure == true);
            console.log(`Test ${test}: ${tests[test].description} ${run ? '' : ' - Skipped due to previous failure'}`);
            if (run) {
                try {
                    tests[test].result = yield tests[test].testFunction();
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
        let failedCount = tests.filter((entry) => !entry.result);
        if (failedCount.length > 0) {
            console.error(`The following test${failedCount.length == 1 ? '' : 's'} failed:`);
            for (let test in tests) {
                if (!tests[test].result) {
                    console.error(`${test} - ${tests[test].description}`);
                }
            }
            console.error(`${failedCount.length} test${failedCount.length == 1 ? '' : 's'} failed`);
        }
        else {
            console.log('All tests passed');
        }
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
        node_assert_1.default.deepStrictEqual(items[i], test[i], `Item type ${i} does not match the test version`);
    }
}
function httpRequest(method, url, body = null, contentType = 'application/json') {
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
            const clientRequest = http_1.default.request(url, { method: method.toUpperCase(), headers: options.headers }, incomingMessage => {
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
//# sourceMappingURL=tests.js.map