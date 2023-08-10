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
var CertTypes;
(function (CertTypes) {
    CertTypes[CertTypes["cert"] = 0] = "cert";
    CertTypes[CertTypes["root"] = 1] = "root";
    CertTypes[CertTypes["intermediate"] = 2] = "intermediate";
    CertTypes[CertTypes["leaf"] = 3] = "leaf";
    CertTypes[CertTypes["key"] = 4] = "key";
})(CertTypes || (CertTypes = {}));
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
    caCountry: 'someCountry',
    caState: 'someState',
    caLocation: 'someLocation',
    caOrganization: 'someOrg',
    caUnit: 'someUnit',
    caCommonName: 'someName',
    caValidFrom: new Date().toISOString(),
    caValidTo: then.toISOString(),
};
var newInt = {
    intCountry: 'intCountry',
    intState: 'intState',
    intLocation: 'intLocation',
    intOrganization: 'intOrg',
    intUnit: 'intUnit',
    intCommonName: 'intName',
    intValidFrom: new Date().toISOString(),
    intValidTo: then.toISOString(),
    intSigner: '1',
};
var newLeaf = {
    leafCountry: 'leafCountry',
    leafState: 'leafState',
    leafLocation: 'leafLocation',
    leafOrganization: 'leafOrg',
    leafUnit: 'leafUnit',
    leafCommonName: 'leafName',
    leafValidFrom: new Date().toISOString(),
    leafValidTo: then.toISOString(),
    leafSigner: '2',
};
let stepNo = 0;
const types = ['root', 'intermediate', 'leaf', 'key'];
(() => __awaiter(void 0, void 0, void 0, function* () {
    let webServer;
    let ws;
    let step = '';
    let msg;
    try {
        // Set up
        step = _step('set up');
        if (!fs_1.default.existsSync(testPath))
            fs_1.default.mkdirSync(testPath);
        fs_1.default.writeFileSync(testConfig, config);
        // Create server
        step = _step('create server');
        let ew = new eventWaiter_1.EventWaiter();
        webServer = (0, child_process_1.spawn)('node', [path_1.default.join(__dirname, '../index.js'), testConfig]);
        webServer.on('error', (err) => console.log(`webserver failed: ${err}`));
        webServer.on('close', (code, signal) => console.log(`Server terminated = code=${code};signal=${signal}`));
        webServer.stdout.on('data', (data) => console.log(data.toString()));
        yield new Promise((resolve) => setTimeout(() => resolve(), 2000));
        step = _step('connect WebSocket');
        const wsQueue = [];
        ws = new ws_1.default('ws://localhost:9997');
        ws.on('error', (err) => { throw err; });
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
        let res;
        step = _step('check database is empty');
        for (let dir in types) {
            step = _step(`get empty ${types[dir]} list`);
            res = yield httpRequest('get', url + '/api/certlist?type=' + types[dir]);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            node_assert_1.default.equal(res.body.files.length, 0, `Failed: Expected zero entries for ${types[dir]} request`);
            console.log(`Passed: zero entries returned for ${types[dir]}`);
            // console.log(JSON.stringify(res, null, 4));
        }
        step = _step('generate ca');
        res = yield httpRequest('post', url + '/api/createcacert', JSON.stringify(newCA));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'someName/someName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 1, id: 1 }, { type: 4, id: 1 }]);
        // console.log(msg);
        console.log('passed');
        step = _step('generate intermediate');
        res = yield httpRequest('post', url + '/api/createIntermediateCert', JSON.stringify(newInt));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName/intName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 2, id: 2 }, { type: 4, id: 2 }]);
        // console.log(msg);
        console.log('passed');
        step = _step('generate leaf');
        res = yield httpRequest('post', url + '/api/createleafcert', JSON.stringify(newLeaf));
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'leafName/leafName_key', 2, 0, 0);
        checkItems(msg.added, [{ type: 3, id: 3 }, { type: 4, id: 3 }]);
        // console.log(msg);
        console.log('passed');
        step = _step('get root certificate list');
        res = yield httpRequest('get', url + '/api/certlist?type=root');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'someName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'root', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 1, `File has incorrect id ${res.body.files[0].id}`);
        let rootId = res.body.files[0].id;
        console.log('passed');
        step = _step('get intermediate certificate list');
        res = yield httpRequest('get', url + '/api/certlist?type=intermediate');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'intName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'intermediate', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 2, `File has incorrect id ${res.body.files[0].id}`);
        let intId = res.body.files[0].id;
        console.log('passed');
        step = _step('get leaf certificate list');
        res = yield httpRequest('get', url + '/api/certlist?type=leaf');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}: ${res.body}`);
        node_assert_1.default.notEqual(res.body.files, null, 'Did not receive the files element');
        node_assert_1.default.equal(res.body.files.length, 1, `Files element is expected to be length 1 but received ${res.body.files.length}`);
        node_assert_1.default.equal(res.body.files[0].name, 'leafName', `File has incorrect name ${res.body.files[0].name}`);
        node_assert_1.default.equal(res.body.files[0].type, 'leaf', `File has incorrect type ${res.body.files[0].type}`);
        node_assert_1.default.equal(res.body.files[0].id, 3, `File has incorrect id ${res.body.files[0].id}`);
        let leafId = res.body.files[0].id;
        console.log('passed');
        step = _step('get certificate details by id');
        res = yield httpRequest('get', url + '/certdetails?id=3');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        console.log('passed');
        step = _step('get key details by id');
        res = yield httpRequest('get', url + '/keydetails?id=3');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        console.log('passed');
        step = _step('check database is populated');
        for (let dir in types) {
            step = _step(`get populated ${types[dir]} list`);
            res = yield httpRequest('get', url + '/certlist?type=' + types[dir]);
            node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
            if (dir != '3') {
                node_assert_1.default.equal(res.body.files.length, 1, `Failed: Expected one entry for ${types[dir]} request`);
                console.log(`Passed: one entry returned for ${types[dir]}`);
            }
            else {
                node_assert_1.default.equal(res.body.files.length, 3, `Failed: Expected three entries for ${types[dir]} request`);
                console.log(`Passed: three entries returned for ${types[dir]}`);
            }
            // console.log(JSON.stringify(res, null, 4));
        }
        step = _step('get root certificate file');
        res = yield httpRequest('get', url + '/api/getcertificatepem?id=' + rootId.toString());
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'someName.pem'), res.body);
        let rootcert = node_forge_1.pki.certificateFromPem(res.body);
        let rski = rootcert.getExtension('subjectKeyIdentifier');
        console.log(JSON.stringify(rski, null, 4));
        console.log('passed');
        step = _step('get intermediate certificate file');
        res = yield httpRequest('get', url + '/api/getcertificatepem?id=' + intId.toString());
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'intName.pem'), res.body);
        let intermediatecert = node_forge_1.pki.certificateFromPem(res.body);
        let iski = intermediatecert.getExtension('subjectKeyIdentifier');
        let iaki = intermediatecert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(rski.value.slice(1), iaki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');
        step = _step('get leaf certificate file');
        res = yield httpRequest('get', url + '/api/getcertificatepem?id=' + leafId.toString());
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'leafName.pem'), res.body);
        let leafcert = node_forge_1.pki.certificateFromPem(res.body);
        let laki = leafcert.getExtension('authorityKeyIdentifier');
        node_assert_1.default.equal(iski.value.slice(1), laki.value.slice(3), 'Authority key identifier does not match parent\'s subject key identifier');
        console.log('passed');
        step = _step('get intermediate key file');
        res = yield httpRequest('get', url + '/api/getkeypem?id=2');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        fs_1.default.writeFileSync(path_1.default.join(testPath, 'intName_key.pem'), res.body);
        step = _step('delete root certificate');
        res = yield httpRequest('delete', url + '/api/deletecert?name=someName');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, '', 0, 2, 1);
        checkItems(msg.updated, [{ type: 4, id: 1 }, { type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 1, id: 1 }]);
        // console.log(msg);
        console.log('passed');
        step = _step('Upload root certificate');
        let cert = fs_1.default.readFileSync(path_1.default.join(testPath, 'someName.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', url + '/api/uploadcert', cert);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'someName', 1, 2, 0);
        checkItems(msg.added, [{ type: 1, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id: 2 }, { type: 4, id: 1 }]);
        console.log('passed');
        step = _step('delete intermediate key');
        res = yield httpRequest('delete', url + '/api/deletekey?name=intName_key');
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, '', 0, 1, 1);
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        checkItems(msg.deleted, [{ type: 4, id: 2 }]);
        // console.log(msg);
        console.log('passed');
        step = _step('Upload intermediate key');
        let key = fs_1.default.readFileSync(path_1.default.join(testPath, 'intName_key.pem'), { encoding: 'utf8' });
        res = yield httpRequest('post', url + '/api/uploadKey', key);
        node_assert_1.default.equal(res.statusCode, 200, `Bad status code from server - ${res.statusCode}`);
        yield ew.EventWait();
        ew.EventReset();
        msg = JSON.parse(wsQueue.shift());
        checkPacket(msg, 'intName_key', 1, 1, 0);
        checkItems(msg.added, [{ type: 4, id: 4 }]);
        checkItems(msg.updated, [{ type: 2, id: 2 }]);
        console.log('passed');
        step = _step('get certificate with no name or id');
        res = yield httpRequest('get', url + '/api/getCertificatePem?xx=bad');
        node_assert_1.default.equal(res.statusCode, 400, 'This should have failed');
        console.log('passed');
        step = _step('get certificate with name not found');
        res = yield httpRequest('get', url + '/api/getCertificatePem?name=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');
        step = _step('get certificate with id not found');
        res = yield httpRequest('get', url + '/api/getCertificatePem?id=bad');
        node_assert_1.default.equal(res.statusCode, 404, 'This should have failed');
        console.log('passed');
        step = _step('tests complete');
    }
    catch (err) {
        console.log(`**** Failed in step ${step}: ${err.message}`);
    }
    finally {
        step = _step('cleanup');
        step = _step('disconnect WebSocket');
        ws.close();
        step = _step('kill server');
        webServer.kill('SIGTERM');
        step = _step('remove files');
        fs_1.default.unlinkSync(path_1.default.join(testPath, 'testconfig.yml'));
        fs_1.default.rmSync(testPath, { recursive: true, force: true });
        step = _step('finish');
        ws;
    }
}))();
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
function _step(msg) {
    console.log(`\nStep: ${++stepNo}: ${msg}`);
    return msg;
}
function httpRequest(method, url, body = null) {
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
                options.headers = { 'Content-Length': Buffer.byteLength(body), 'Content-Type': 'application/json' };
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