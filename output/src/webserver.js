"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.WebServer = void 0;
const node_fs_1 = require("node:fs");
const path_1 = __importDefault(require("path"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
const promises_1 = require("fs/promises");
const crypto_1 = __importDefault(require("crypto"));
const node_forge_1 = require("node-forge");
const lokijs_1 = __importStar(require("lokijs"));
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const serve_favicon_1 = __importDefault(require("serve-favicon"));
const ws_1 = __importDefault(require("ws"));
const stream_1 = require("stream");
const log4js = __importStar(require("log4js"));
const eventWaiter_1 = require("./utility/eventWaiter");
const exists_1 = require("./utility/exists");
const ExtensionBasicConstraints_1 = require("./extensions/ExtensionBasicConstraints");
const ExtensionKeyUsage_1 = require("./extensions/ExtensionKeyUsage");
const ExtensionAuthorityKeyIdentifier_1 = require("./extensions/ExtensionAuthorityKeyIdentifier");
const ExtensionSubjectKeyIdentifier_1 = require("./extensions/ExtensionSubjectKeyIdentifier");
const ExtensionExtKeyUsage_1 = require("./extensions/ExtensionExtKeyUsage");
const ExtensionSubjectAltName_1 = require("./extensions/ExtensionSubjectAltName");
const CertTypes_1 = require("./webservertypes/CertTypes");
const userAgentOS_1 = require("./webservertypes/userAgentOS");
const CertError_1 = require("./webservertypes/CertError");
const CertMultiError_1 = require("./webservertypes/CertMultiError");
const logger = log4js.getLogger();
logger.level = "debug";
/**
 * @classdesc Web server to help maintain test certificates and keys in the file system and a database.
 */
class WebServer {
    static createWebServer(config) {
        if (!WebServer.instance) {
            WebServer.instance = new WebServer(config);
        }
        return WebServer.instance;
    }
    static getWebServer() {
        return WebServer.instance;
    }
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    /**
     * @constructor
     * @param config Configuration information such as port, etc.
     */
    constructor(config) {
        this.DB_NAME = 'certs.db';
        this._app = (0, express_1.default)();
        this._ws = new ws_1.default.Server({ noServer: true });
        this._certificate = null;
        this._key = null;
        this._version = 'v' + require('../../package.json').version;
        this._currentVersion = 4;
        this._config = config;
        this._port = config.certServer.port;
        this._dataPath = config.certServer.root;
        if (config.certServer.certificate || config.certServer.key) {
            if (!config.certServer.certificate || !config.certServer.key) {
                throw new Error('Certificate and key must both be present of neither be present');
            }
            this._certificate = fs_1.default.readFileSync(config.certServer.certificate, { encoding: 'utf8' });
            this._key = fs_1.default.readFileSync(config.certServer.key, { encoding: 'utf8' });
        }
        if (config.certServer.subject.C && config.certServer.subject.C.length != 2) {
            throw new Error(`Invalid country code ${config.certServer.subject.C} - must be two characters`);
        }
        this._certificatesPath = path_1.default.join(this._dataPath, 'certificates');
        this._privatekeysPath = path_1.default.join(this._dataPath, 'privatekeys');
        this._dbPath = path_1.default.join(this._dataPath, 'db');
        if (!(0, node_fs_1.existsSync)(this._dataPath))
            (0, node_fs_1.mkdirSync)(this._dataPath, { recursive: true });
        if (!(0, node_fs_1.existsSync)(this._certificatesPath))
            (0, node_fs_1.mkdirSync)(this._certificatesPath);
        if (!(0, node_fs_1.existsSync)(this._privatekeysPath))
            (0, node_fs_1.mkdirSync)(this._privatekeysPath);
        if (!(0, node_fs_1.existsSync)(this._dbPath))
            (0, node_fs_1.mkdirSync)(this._dbPath);
        this._app.set('views', path_1.default.join(__dirname, '../../web/views'));
        this._app.set('view engine', 'pug');
    }
    /**
     * Starts the webserver and defines the express routes.
     *
     * @returns Promise\<void>
     */
    start() {
        return __awaiter(this, void 0, void 0, function* () {
            const csHost = ({ protocol, hostname, port }) => `${protocol}://${hostname}:${port}`;
            logger.info(`CertServer starting - ${this._version}`);
            let getCollections = () => {
                if (null == (certificates = db.getCollection('certificates'))) {
                    certificates = db.addCollection('certificates', {});
                }
                if (null == (privateKeys = db.getCollection('privateKeys'))) {
                    privateKeys = db.addCollection('privateKeys', {});
                }
                if (null == (dbVersion = db.getCollection('dbversion'))) {
                    dbVersion = db.addCollection('dbversion', {});
                }
                ew.EventSet();
            };
            try {
                var ew = new eventWaiter_1.EventWaiter();
                var certificates = null;
                var privateKeys = null;
                var dbVersion = null;
                var db = new lokijs_1.default(path_1.default.join(this._dbPath.toString(), this.DB_NAME), {
                    autosave: true,
                    autosaveInterval: 2000,
                    adapter: new lokijs_1.LokiFsAdapter(),
                    autoload: true,
                    autoloadCallback: getCollections,
                    verbose: true,
                    persistenceMethod: 'fs'
                });
                yield ew.EventWait();
                this._db = db;
                this._certificates = certificates;
                this._privateKeys = privateKeys;
                this._dbVersion = dbVersion;
                yield this._dbInit();
            }
            catch (err) {
                logger.fatal('Failed to initialize the database: ' + err.message);
                process.exit(4);
            }
            //const jsonParser = bodyParser.json();
            this._app.use(express_1.default.urlencoded({ extended: true }));
            this._app.use((0, serve_favicon_1.default)(path_1.default.join(__dirname, "../../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
            this._app.use(express_1.default.json({ type: '*/json' }));
            this._app.use(express_1.default.text({ type: 'text/plain' }));
            this._app.use(express_1.default.text({ type: 'application/x-www-form-urlencoded' }));
            this._app.use(express_1.default.text({ type: 'application/json' }));
            this._app.use('/scripts', express_1.default.static(path_1.default.join(__dirname, '../../web/scripts')));
            this._app.use('/styles', express_1.default.static(path_1.default.join(__dirname, '../../web/styles')));
            this._app.use('/icons', express_1.default.static(path_1.default.join(__dirname, '../../web/icons')));
            this._app.use('/files', express_1.default.static(path_1.default.join(__dirname, '../../web/files')));
            this._app.use('/images', express_1.default.static(path_1.default.join(__dirname, '../../web/images')));
            this._app.use((0, express_fileupload_1.default)());
            this._app.use((request, _response, next) => {
                logger.debug(`${request.method} ${request.url}`);
                next();
            });
            this._app.get('/', (_request, response) => {
                response.render('index', {
                    title: 'Certificates Management Home',
                    C: this._config.certServer.subject.C,
                    ST: this._config.certServer.subject.ST,
                    L: this._config.certServer.subject.L,
                    O: this._config.certServer.subject.O,
                    OU: this._config.certServer.subject.OU,
                    version: this._version,
                });
            });
            this._app.get('/api/test', (request, response) => __awaiter(this, void 0, void 0, function* () {
                response.setHeader('content-type', 'application/text');
                let userAgent = request.get('User-Agent');
                let os;
                if (request.query.os) {
                    if (request.query.os.toUpperCase() in userAgentOS_1.userAgentOS) {
                        let work = request.query.os.toUpperCase();
                        os = userAgentOS_1.userAgentOS[work];
                        logger.debug(`OS specified as ${userAgentOS_1.userAgentOS[os]}`);
                    }
                    else {
                        return response.status(400).json({ error: `OS invalid or unsupported ${request.query.os}` });
                    }
                }
                else {
                    os = WebServer._guessOs(userAgent);
                    logger.debug(`${userAgent} guessed to be ${userAgentOS_1.userAgentOS[os]}`);
                }
                let hostname = `${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}`;
                let readable;
                if (os == userAgentOS_1.userAgentOS.LINUX || os == userAgentOS_1.userAgentOS.MAC) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.sh"`);
                    readable = stream_1.Readable.from([
                        `export CERTSERVER_HOST=${hostname}\n`,
                        `export REQUEST_PATH=${request.path}\n`,
                    ].concat(((yield (0, promises_1.readFile)('src/files/linuxhelperscript.sh', { encoding: 'utf8' })).split('\n').map((l) => l + '\n'))));
                }
                else if (os == userAgentOS_1.userAgentOS.WINDOWS) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.ps1"`);
                    readable = stream_1.Readable.from([
                        `Set-Item "env:CERTSERVER_HOST" -Value "${hostname}"\n`,
                        `Set-Item "env:REQUEST_PATH" -Value "${request.path}"\n`,
                    ].concat(((yield (0, promises_1.readFile)('src/files/windowshelperscript.ps1', { encoding: 'utf8' })).split('\n').map((l) => l + '\n'))));
                }
                else {
                    return response.status(400).json({ error: `No script for OS ${userAgentOS_1.userAgentOS[os]}}` });
                }
                readable.pipe(response);
            }));
            this._app.get('/api/helper', (request, response) => {
                response.setHeader('content-type', 'application/text');
                let userAgent = request.get('User-Agent');
                let os;
                if (request.query.os) {
                    if (request.query.os.toUpperCase() in userAgentOS_1.userAgentOS) {
                        let work = request.query.os.toUpperCase();
                        os = userAgentOS_1.userAgentOS[work];
                        logger.debug(`OS specified as ${userAgentOS_1.userAgentOS[os]}`);
                    }
                    else {
                        return response.status(400).json({ error: `OS invalid or unsupported ${request.query.os}` });
                    }
                }
                else {
                    os = WebServer._guessOs(userAgent);
                    logger.debug(`${userAgent} guessed to be ${userAgentOS_1.userAgentOS[os]}`);
                }
                let readable;
                if (os == userAgentOS_1.userAgentOS.LINUX || os == userAgentOS_1.userAgentOS.MAC) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.sh"`);
                    readable = stream_1.Readable.from([
                        `function getcert(){ wget --content-disposition ${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/getCertificatePem?id=$@; }\n`,
                        `function getkey(){ wget --content-disposition ${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/getKeyPem?id=$@; }\n`,
                        `function getchain(){ wget --content-disposition ${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/chainDownload?id=$@; }\n`,
                        `function pushcert(){ curl -X POST -H "Content-Type: text/plain" --data-binary @$@ ${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/uploadCert; }\n`,
                        `function pushkey(){ curl -X POST -H "Content-Type: text/plain" --data-binary @$@ ${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/uploadKey; }\n`
                    ]);
                }
                else if (os == userAgentOS_1.userAgentOS.WINDOWS) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.ps1"`);
                    readable = stream_1.Readable.from([
                        `function Get-Filename {\n`,
                        `param (\n`,
                        `$url\n`,
                        `)\n`,
                        `$filename = ''\n`,
                        `try {\n`,
                        `$req = Invoke-WebRequest -Uri $url\n`,
                        `$filename = $req.Headers.'Content-Disposition'.split(';')[1].Split('=')[1].Replace('"', '')\n`,
                        `}\n`,
                        `catch {\n`,
                        `Write-Host 'Request failed'\n`,
                        `Write-Host $_.ErrorDetails\n`,
                        `}\n`,
                        `return $filename\n`,
                        `}\n`,
                        `function Get-URIPrefix {\n`,
                        `return "${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/"\n`,
                        `}\n`,
                        `function Get-File {\n`,
                        `param (\n`,
                        `$uriSuffix\n`,
                        `)\n`,
                        `$prefix = Get-URIPrefix\n`,
                        `$uri = $prefix + $uriSuffix\n`,
                        `$filename = Get-Filename $uri\n`,
                        `if ($filename -ne '') {\n`,
                        `Invoke-WebRequest -Uri $uri -OutFile ".\\$filename"\n`,
                        `Write-Output ".\\$filename written"\n`,
                        `}\n`,
                        `}\n`,
                        `function Get-CertPem {\n`,
                        `param (\n`,
                        `$certificateId\n`,
                        `)\n`,
                        `$uri = "getCertificatePem?id=$certificateId"\n`,
                        `Get-File $uri\n`,
                        `}\n`,
                        `function Get-Chain {\n`,
                        `param (\n`,
                        `$certificateId\n`,
                        `)\n`,
                        `$uri = "chainDownload?id=$certificateId"\n`,
                        `Get-File $uri\n`,
                        `}\n`,
                        `function Get-KeyPem {\n`,
                        `param (\n`,
                        `$keyId\n`,
                        `)\n`,
                        `$uri = "getKeyPem?id=$keyId"\n`,
                        `Get-File $uri\n`,
                        `}\n`,
                        `function Push-CertPem {\n`,
                        `param (\n`,
                        `$certName\n`,
                        `)\n`,
                        `$uri = Get-URIPrefix + "/api/uploadCert"\n`,
                        `Invoke-RestMethod -Method Post -Uri $uri -InFile $certName -ContentType 'text/plain'\n`,
                        `}\n`,
                        `function Push-KeyPem {\n`,
                        `param (\n`,
                        `$keyName\n`,
                        `)\n`,
                        `$uri = Get-URIPrefix + "/api/uploadKey"\n`,
                        `Invoke-RestMethod -Method Post -Uri $uri -InFile $keyName -ContentType 'text/plain'\n`,
                        `}\n`,
                    ]);
                }
                else {
                    return response.status(400).json({ error: `No script for OS ${userAgentOS_1.userAgentOS[os]}}` });
                }
                readable.pipe(response);
            });
            this._app.post('/createCACert', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/createCACert';
                next();
            }));
            this._app.post('/createIntermediateCert', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/createIntermediateCert';
                next();
            }));
            this._app.post('/createLeafCert', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/createLeafCert';
                next();
            }));
            this._app.post('/updateCertTag', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/updateCertTag';
                request.query['id'] = request.body.toTag;
                next();
            }));
            /**
             * Upload pem format files. These can be key, a certificate, or a file that
             * contains keys or certificates.
             */
            this._app.post('/uploadPem', ((request, response) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                // FUTURE: Allow der and pfx files to be submitted
                if (!request.files || Object.keys(request.files).length == 0) {
                    return response.status(400).json({ error: 'No file selected' });
                }
                try {
                    let compareResultItem = (l, r) => {
                        return l.type == r.type && l.id == r.id;
                    };
                    let mergeResults = (accumulator, next) => {
                        let i;
                        for (i in next.added) {
                            if (!accumulator.added.some((a) => compareResultItem(a, next.added[i]))) {
                                accumulator.added.push(next.added[i]);
                            }
                        }
                        for (i in next.updated) {
                            if (!accumulator.updated.some((a) => compareResultItem(a, next.updated[i]))) {
                                accumulator.updated.push(next.updated[i]);
                            }
                        }
                        for (i in next.deleted) {
                            if (!accumulator.deleted.some((a) => compareResultItem(a, next.deleted[i]))) {
                                accumulator.deleted.push(next.deleted[i]);
                            }
                        }
                        return accumulator;
                    };
                    let files = request.files.certFile;
                    if (!Array.isArray(files)) {
                        files = [files];
                    }
                    let result = { name: 'multiple', added: [], updated: [], deleted: [] };
                    let messages = [];
                    for (let i in files) {
                        let msg = node_forge_1.pem.decode(files[i].data);
                        for (let j in msg) {
                            logger.debug(`Received ${msg[j].type}`);
                            try {
                                let oneRes = null;
                                if (msg[j].type.includes('CERTIFICATE')) {
                                    oneRes = yield this._tryAddCertificate({ filename: files[i].name, pemString: node_forge_1.pem.encode(msg[j], { maxline: 64 }) });
                                    messages.push({ level: 0, message: `Certificate ${files[i].name} uploaded` });
                                }
                                else if (msg[j].type.includes('KEY')) {
                                    oneRes = yield this._tryAddKey({ filename: files[i].name, pemString: files[i].data.toString() });
                                    messages.push({ level: 0, message: `Key ${files[i].name} uploaded` });
                                }
                                else {
                                    throw new CertError_1.CertError(409, `File ${files[i].name} is not a certificate or a key`);
                                }
                                result = mergeResults(result, oneRes);
                            }
                            catch (err) {
                                messages.push({ level: 1, message: err.message });
                            }
                        }
                    }
                    if (result.added.length + result.updated.length + result.deleted.length > 0) {
                        this._broadcast(result);
                    }
                    return response.status(200).json(messages);
                }
                catch (err) {
                    logger.error(`Upload files failed: ${err.message}`);
                    return response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json({ error: err.message });
                }
            })));
            this._app.delete('/deleteCert', ((request, _response, next) => {
                request.url = '/api/deleteCert';
                next();
            }));
            this._app.get('/certList', (request, _response, next) => {
                request.url = '/api/certList';
                next();
            });
            this._app.get('/certDetails', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/certDetails';
                next();
            }));
            this._app.delete('/deleteKey', ((request, _response, next) => {
                request.url = '/api/deleteKey';
                next();
            }));
            this._app.get('/keyList', (request, _response, next) => {
                request.url = '/certList';
                next();
            });
            this._app.get('/keyDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _b;
                try {
                    let k = this._resolveKeyQuery(request.query);
                    if (k) {
                        let retVal = this._getKeyBrief(k);
                        response.status(200).json(retVal);
                    }
                    else {
                        response.status(404).json({ error: 'Key not found' });
                    }
                }
                catch (err) {
                    response.status((_b = err.status) !== null && _b !== void 0 ? _b : 500).json({ error: err.message });
                }
            }));
            this._app.post('/api/createCaCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _c;
                try {
                    logger.debug(request.body);
                    let certInput = WebServer._validateCertificateInput(CertTypes_1.CertTypes.root, request.body);
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._setAttributes(certInput.subject);
                    const extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true, critical: true }),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                        // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, keyIdentifier: true }),
                        new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = certInput.validFrom;
                    cert.validity.notAfter = certInput.validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(privateKey, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    let certResult = yield this._tryAddCertificate({ pemString: node_forge_1.pki.certificateToPem(cert) });
                    let keyResult = yield this._tryAddKey({ pemString: node_forge_1.pki.privateKeyToPem(privateKey) });
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let certId = certResult.added[0].id;
                    let keyId = keyResult.added[0].id;
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, ids: { certificateId: certId, keyId: keyId } });
                }
                catch (err) {
                    return response.status((_c = err.status) !== null && _c !== void 0 ? _c : 500).json({ error: err.message });
                }
            }));
            this._app.post('/api/createIntermediateCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let certInput = WebServer._validateCertificateInput(CertTypes_1.CertTypes.intermediate, request.body);
                    const cRow = this._certificates.findOne({ $loki: parseInt(certInput.signer) });
                    const kRow = this._privateKeys.findOne({ $loki: cRow.keyId });
                    if (!cRow || !kRow) {
                        return response.status(404).json({ error: 'Signing certificate or key are either missing or invalid' });
                    }
                    const c = yield this._pkiCertFromRow(cRow);
                    const k = yield (this._pkiKeyFromRow(kRow, certInput.password));
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._setAttributes(certInput.subject);
                    const extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true, critical: true }),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                        new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
                        new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}),
                    ];
                    if (certInput.san.domains.length > 0 || certInput.san.IPs.length > 0) {
                        let sal = {};
                        sal.domains = certInput.san.domains;
                        sal.IPs = certInput.san.IPs;
                        extensions.push(new ExtensionSubjectAltName_1.ExtensionSubjectAltName(sal));
                    }
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = certInput.validFrom;
                    cert.validity.notAfter = certInput.validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Sign with parent certificate's private key
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    let certResult = yield this._tryAddCertificate({ pemString: node_forge_1.pki.certificateToPem(cert) });
                    let keyResult = yield this._tryAddKey({ pemString: node_forge_1.pki.privateKeyToPem(privateKey) });
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let certId = certResult.added[0].id;
                    let keyId = keyResult.added[0].id;
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name} added`, ids: { certificateId: certId, keyId: keyId } });
                }
                catch (err) {
                    logger.error(`Failed to create intermediate certificate: ${err.message}`);
                    return response.status(500).json({ error: err.message });
                }
            }));
            this._app.post('/api/createLeafCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let certInput = WebServer._validateCertificateInput(CertTypes_1.CertTypes.leaf, request.body);
                    const cRow = this._certificates.findOne({ $loki: parseInt(certInput.signer) });
                    const kRow = this._privateKeys.findOne({ pairId: cRow.$loki });
                    if (!cRow || !kRow) {
                        return response.status(500).json({ error: 'Signing certificate or key are either missing or invalid' });
                    }
                    const c = yield this._pkiCertFromRow(cRow);
                    const k = yield (this._pkiKeyFromRow(kRow, certInput.password));
                    ;
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._setAttributes(certInput.subject);
                    let sal = {};
                    sal.domains = certInput.san.domains;
                    sal.IPs = certInput.san.IPs;
                    let extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: false }),
                        new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
                        new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
                        new ExtensionExtKeyUsage_1.ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true, }),
                        new ExtensionSubjectAltName_1.ExtensionSubjectAltName(sal),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = certInput.validFrom;
                    cert.validity.notAfter = certInput.validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Sign the certificate with the parent's key
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    let certResult = yield this._tryAddCertificate({ pemString: node_forge_1.pki.certificateToPem(cert) });
                    let keyResult = yield this._tryAddKey({ pemString: node_forge_1.pki.privateKeyToPem(privateKey) });
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let certId = certResult.added[0].id;
                    let keyId = keyResult.added[0].id;
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name} added`, ids: { certificateId: certId, keyId: keyId } });
                }
                catch (err) {
                    logger.error(`Error creating leaf certificate: ${err.message}`);
                    return response.status(500).json({ error: err.message });
                }
            }));
            this._app.get('/api/certName', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _d, _e;
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    response.status(200).json({ name: c.subject.CN, id: c.$loki, tags: (_d = c.tags) !== null && _d !== void 0 ? _d : [] });
                }
                catch (err) {
                    response.status((_e = err.status) !== null && _e !== void 0 ? _e : 500).json({ error: err.message });
                }
            }));
            this._app.get('/api/certDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _f;
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let retVal = this._getCertificateBrief(c);
                    response.status(200).json(retVal);
                }
                catch (err) {
                    if (err instanceof CertMultiError_1.CertMultiError) {
                        response.status(err.status).json({ error: err.message, ids: err.certs });
                    }
                    else {
                        response.status((_f = err.status) !== null && _f !== void 0 ? _f : 500).json({ error: err.message });
                    }
                }
            }));
            this._app.get('/api/keyList', (request, _response, next) => {
                request.url = '/api/certList';
                request.query = { type: 'key' };
                next();
            });
            this._app.get('/api/certList', (request, response) => {
                let type = CertTypes_1.CertTypes[request.query.type];
                if (type == undefined) {
                    response.status(404).json({ error: `Directory ${request.query.type} not found` });
                }
                else {
                    let retVal = [];
                    if (type != CertTypes_1.CertTypes.key) {
                        retVal = this._certificates.chain().find({ type: type }).sort((l, r) => l.name.localeCompare(r.name)).data().map((entry) => {
                            var _a;
                            return { name: entry.subject.CN, type: CertTypes_1.CertTypes[type].toString(), id: entry.$loki, tags: (_a = entry.tags) !== null && _a !== void 0 ? _a : [], keyId: entry.keyId };
                        });
                    }
                    else {
                        retVal = this._privateKeys.chain().find().sort((l, r) => {
                            // Circumvent bug that caused broken keys
                            // let lStr = l.pairCN? l.pairCN : '';
                            // let rStr = r.pairCN? r.pairCN : '';
                            return l.name.localeCompare(r.name);
                        }).data().map((entry) => {
                            return {
                                name: entry.name,
                                type: CertTypes_1.CertTypes[type].toString(),
                                id: entry.$loki
                            };
                        });
                    }
                    response.status(200).json({ files: retVal });
                }
            });
            this._app.get('/api/getCertificatePem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _g;
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    response.download(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), c.name + '.pem', (err) => {
                        if (err) {
                            return response.status(500).json({ error: `Failed to file for ${request.query}: ${err.message}` });
                        }
                    });
                }
                catch (err) {
                    logger.error('Certificate download failed: ', err.message);
                    return response.status((_g = err.status) !== null && _g !== void 0 ? _g : 500).json({ error: err.message });
                }
            }));
            this._app.post('/api/uploadCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _h;
                // FUTURE Allow multiple concatenated pem files
                // FUTURE Merge uploadCert and uploadKey into uploadFile
                try {
                    if (request.headers['content-type'] != 'text/plain') {
                        return response.status(400).json({ error: 'Content-Type must be text/plain' });
                    }
                    if (!request.body.includes('\n')) {
                        return response.status(400).json({ error: 'Certificate must be in standard 64 byte line length format - try --data-binary with curl' });
                    }
                    let msg = node_forge_1.pem.decode(request.body);
                    if (msg.length == 0) {
                        return response.status(400).json({ error: 'Could not decode the file as a pem certificate' });
                    }
                    else if (msg.length > 1) {
                        return response.status(400).json({ error: 'Multiple pems in a single file are not supported' });
                    }
                    else if (!msg[0].type.includes('CERTIFICATE')) {
                        return response.status(400).json({ error: `Expecting CERTIFICATE - received ${msg[0].type}` });
                    }
                    let result = yield this._tryAddCertificate({ pemString: request.body });
                    this._broadcast(result);
                    return response.status(200).json({ message: `Certificate ${result.name} of type ${CertTypes_1.CertTypes[result.added[0].type]} added`, ids: { certificateId: result.added[0].id } });
                }
                catch (err) {
                    response.status((_h = err.status) !== null && _h !== void 0 ? _h : 500).json({ error: err.message });
                }
            }));
            this._app.delete('/api/deleteCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _j;
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let result = yield this._tryDeleteCert(c);
                    this._broadcast(result);
                    return response.status(200).json({ message: `Certificate ${result.name} deleted` });
                }
                catch (err) {
                    return response.status((_j = err.status) !== null && _j !== void 0 ? _j : 500).json(JSON.stringify({ error: err.message }));
                }
            }));
            this._app.post('/api/updateCertTag', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _k;
                try {
                    let tags = request.body;
                    if (tags.tags === undefined)
                        tags.tags = [];
                    else if (!Array.isArray(tags.tags))
                        tags.tags = [tags.tags];
                    let cleanedTags = tags.tags.map((t) => t.trim()).filter((t) => t != '');
                    for (let tag in cleanedTags) {
                        if (tag.match(/[;<>\(\)\{\}\/]/) !== null)
                            throw new CertError_1.CertError(400, 'Tags cannot contain ; < > / { } ( )');
                    }
                    let result = this._resolveCertificateUpdate(request.query, (c) => {
                        c.tags = cleanedTags;
                    });
                    this._broadcast(result);
                    return response.status(200).json({ message: `Certificate tags updated` });
                }
                catch (err) {
                    return response.status((_k = err.status) !== null && _k !== void 0 ? _k : 500).json({ error: err.message });
                    // return response.status(err.status?? 500).json(`{"error": "${err.message}"}`);
                }
            }));
            this._app.get('/api/keyname', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _l;
                try {
                    let k = this._resolveKeyQuery(request.query);
                    response.status(200).json({ name: k.name, id: k.$loki, tags: [] });
                }
                catch (err) {
                    response.status((_l = err.status) !== null && _l !== void 0 ? _l : 500).json({ error: err.message });
                }
            }));
            this._app.post('/api/uploadKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (request.headers['content-type'] != 'text/plain') {
                        return response.status(400).send('Content type must be text/plain');
                    }
                    if (!request.body.includes('\n')) {
                        return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary with curl');
                    }
                    let msg = node_forge_1.pem.decode(request.body);
                    if (msg.length == 0) {
                        return response.status(400).json({ error: 'Could not decode the file as a pem key' });
                    }
                    else if (msg.length > 1) {
                        return response.status(400).json({ error: 'Multiple pems in a single file are not supported' });
                    }
                    else if (!msg[0].type.includes('KEY')) {
                        return response.status(400).json({ error: `Expecting KEY - received ${msg[0].type}` });
                    }
                    let result = yield this._tryAddKey({ pemString: request.body, password: request.query.password });
                    this._broadcast(result);
                    return response.status(200).json({ message: `Key ${result.name} added`, ids: { keyId: result.added[0].id } });
                }
                catch (err) {
                    response.status(500).json({ error: err.message });
                }
            }));
            this._app.delete('/api/deleteKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _m;
                try {
                    let k = this._resolveKeyQuery(request.query);
                    let result = yield this._tryDeleteKey(k);
                    this._broadcast(result);
                    return response.status(200).json({ message: `Key ${result.name} deleted` });
                }
                catch (err) {
                    return response.status((_m = err.status) !== null && _m !== void 0 ? _m : 500).json({ error: err.message });
                }
            }));
            this._app.get('/api/getKeyPem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _o;
                try {
                    let k = this._resolveKeyQuery(request.query);
                    response.download(this._getKeysDir(WebServer._getKeyFilenameFromRow(k)), k.name + '.pem', (err) => {
                        if (err) {
                            return response.status(500).json({ error: `Failed to file for ${request.query.id}: ${err.message}` });
                        }
                    });
                }
                catch (err) {
                    logger.error('Key download failed: ', err.message);
                    return response.status((_o = err.status) !== null && _o !== void 0 ? _o : 500).json({ error: err.message });
                }
            }));
            this._app.get('/api/ChainDownload', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _p;
                // BUG - Breaks if there chain is not complete
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let fileData = yield this._getChain(c);
                    response.type('application/text');
                    response.setHeader('Content-Disposition', `inline; filename=${c.name}_chain.pem`);
                    response.send(fileData);
                }
                catch (err) {
                    logger.error('Chain download failed: ' + err.message);
                    return response.status((_p = err.status) !== null && _p !== void 0 ? _p : 500).json({ error: err.message });
                }
            }));
            let server;
            try {
                if (this._certificate) {
                    const options = {
                        cert: this._certificate,
                        key: this._key,
                    };
                    server = https_1.default.createServer(options, this._app).listen(this._port, '0.0.0.0');
                }
                else {
                    server = http_1.default.createServer(this._app).listen(this._port, '0.0.0.0');
                    server.on('error', (err) => {
                        logger.fatal(`Webserver error: ${err.message}`);
                        process.exit(4);
                    });
                }
                logger.info('Listening on ' + this._port);
            }
            catch (err) {
                logger.fatal(`Failed to start webserver: ${err}`);
            }
            server.on('upgrade', (request, socket, head) => __awaiter(this, void 0, void 0, function* () {
                try {
                    this._ws.handleUpgrade(request, socket, head, (ws) => {
                        ws.send('Connected');
                        logger.debug('WebSocket client connected');
                    });
                }
                catch (err) {
                    logger.error('Upgrade failed: ' + err.message);
                    socket.destroy();
                }
            }));
        });
    }
    /**
     * Ensures that the certificates and keys in the file system are consistent with the entries in the database and vice-versa. Thus, files found
     * in the file system that are not in the database will be added, rows found in the database that do not have matching files will be deleted.
     *
     * @private
     * @returns Promise\<void>
     */
    _dbInit() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let version = this._dbVersion.where((_v) => true);
                    if (version.length > 1) {
                        logger.fatal('Version table is corrupt. Should only contain one row');
                        process.exit(4);
                    }
                    else if (version.length == 0) {
                        this._dbVersion.insert({ version: this._currentVersion });
                    }
                    else {
                        this._currentVersion = version[0].version;
                    }
                    logger.info(`Database version is ${this._currentVersion}`);
                    if (WebServer._lowestDBVersion > this._currentVersion) {
                        logger.error(`The lowest database version this release can operate with is ${WebServer._lowestDBVersion} but the database is at ${this._currentVersion}`);
                        logger.fatal('Please install an earlier release of this application');
                        process.exit(4);
                    }
                    let files;
                    let certRows = this._certificates.chain().simplesort('name').data();
                    certRows.forEach((row) => {
                        if (!fs_1.default.existsSync(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(row)))) {
                            logger.warn(`Certificate ${row.name} not found - removed`);
                            this._certificates.remove(row);
                            this._certificates.chain().find({ $loki: row.signedById }).update((r) => {
                                r.signedById = null;
                                logger.warn(`Removed signedBy from ${r.name}`);
                            });
                            this._privateKeys.chain().find({ pairId: row.$loki }).update((k) => {
                                // k.pairSerial = null;
                                k.pairCN = null;
                                k.pairId = null;
                                logger.warn(`Removed relationship to private key from ${k.name}`);
                            });
                        }
                    });
                    files = fs_1.default.readdirSync(this._certificatesPath);
                    let adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        let cert = this._certificates.findOne({ $loki: WebServer._getIdFromFileName(file) });
                        if (!cert) {
                            try {
                                adding.push(this._tryAddCertificate({ filename: this._getCertificatesDir(file) }));
                            }
                            catch (err) { }
                        }
                    }));
                    yield Promise.all(adding);
                    let nonRoot = this._certificates.find({ '$and': [{ 'type': { '$ne': CertTypes_1.CertTypes.root } }, { signedById: null }] });
                    for (let i = 0; i < nonRoot.length; i++) {
                        let signer = yield this._findSigner(node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(nonRoot[i])), { encoding: 'utf8' })));
                        if (signer != null) {
                            logger.info(`${nonRoot[i].name} is signed by ${signer.name}`);
                            // nonRoot[i].signedBy = signer.serialNumber;
                            nonRoot[i].signedById = signer.$loki;
                            this._certificates.update(nonRoot[i]);
                        }
                    }
                    let keyRows = this._privateKeys.chain().simplesort('name').data();
                    keyRows.forEach((key) => {
                        if (!(0, node_fs_1.existsSync)(this._getKeysDir(WebServer._getKeyFilenameFromRow(key)))) {
                            logger.warn(`Key ${key.name} not found - removed`);
                            this._privateKeys.remove(key);
                        }
                    });
                    files = fs_1.default.readdirSync(this._privatekeysPath);
                    adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        // logger.debug(path.basename(file));
                        let key = this._privateKeys.findOne({ $loki: WebServer._getIdFromFileName(file) });
                        if (!key) {
                            try {
                                adding.push(this._tryAddKey({ filename: path_1.default.join(this._privatekeysPath, file) }));
                            }
                            catch (err) {
                                logger.debug('WTF');
                            }
                        }
                    }));
                    yield Promise.allSettled(adding);
                    this._db.saveDatabase((err) => {
                        if (err)
                            reject(err);
                        else
                            resolve();
                    });
                    yield this._databaseFixUp();
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Tries to add a new certificate to the system. During that process, it will also check to see if there is already a key pair in the system
     * and will link the two if there is. It will also look for a signing certificate and link that and any certificates that have been signed by
     * this certificate and link those.
     *
     * @param input Either the filename of a file containing the pem or the pem in a string
     * @returns Synopsis of modifications made to the databases
     */
    _tryAddCertificate(input) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                var _a, _b;
                try {
                    if (!input.pemString) {
                        logger.info(`Trying to add ${path_1.default.basename(input.filename)}`);
                        if (!(yield (0, exists_1.exists)(input.filename))) {
                            reject(new CertError_1.CertError(404, `${path_1.default.basename(input.filename)} does not exist`));
                        }
                        input.pemString = yield (0, promises_1.readFile)(input.filename, { encoding: 'utf8' });
                    }
                    let msg = node_forge_1.pem.decode(input.pemString)[0];
                    logger.debug(`Received ${msg.type}`);
                    if (msg.type != 'CERTIFICATE') {
                        throw new CertError_1.CertError(400, 'Unsupported type ' + msg.type);
                    }
                    let result = { name: '', added: [], updated: [], deleted: [] };
                    let c = node_forge_1.pki.certificateFromPem(input.pemString);
                    logger.debug(`Adding certificate ${c.subject.getField('CN').value}`);
                    let signedById = null;
                    // See if we already have this certificate
                    let fingerprint256 = new crypto_1.default.X509Certificate(input.pemString).fingerprint256;
                    if (this._certificates.findOne({ fingerprint256: fingerprint256 }) != null) {
                        throw new CertError_1.CertError(409, `${c.subject.getField('CN').value} serial number ${c.serialNumber} is a duplicate - ignored`);
                    }
                    // See if this is a root, intermediate, or leaf
                    let type;
                    if (c.isIssuer(c)) {
                        type = CertTypes_1.CertTypes.root;
                        signedById = -1;
                    }
                    else {
                        let bc = c.getExtension('basicConstraints');
                        if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                            type = CertTypes_1.CertTypes.intermediate;
                        }
                        else {
                            type = CertTypes_1.CertTypes.leaf;
                        }
                        // See if any existing certificates signed this one
                        let signer = yield this._findSigner(c);
                        if (signer != null) {
                            signedById = signer.$loki;
                        }
                    }
                    // Generate a filename for the common name
                    let name = WebServer._sanitizeName(c.subject.getField('CN').value);
                    result.name = c.subject.getField('CN').value;
                    logger.info(`Certificate ${name} added`);
                    // This is declared as returning the wrong type hence cast below
                    let newRecord = (this._certificates.insert({
                        name: name,
                        type: type,
                        serialNumber: c.serialNumber,
                        publicKey: c.publicKey,
                        // privateKey: null, 
                        signedById: signedById,
                        issuer: WebServer._getSubject(c.issuer),
                        subject: WebServer._getSubject(c.subject),
                        notBefore: c.validity.notBefore,
                        notAfter: c.validity.notAfter,
                        // havePrivateKey: undefined,
                        fingerprint: new crypto_1.default.X509Certificate(input.pemString).fingerprint,
                        fingerprint256: fingerprint256,
                        tags: [],
                        keyId: null
                    })); // Return value erroneously omits LokiObj
                    result.added.push({ type: type, id: newRecord.$loki });
                    // If the certificate is self-signed update the id in the record
                    if (signedById == -1) {
                        let c = this._certificates.findOne({ $loki: newRecord.$loki });
                        if (c) {
                            c.signedById = newRecord.$loki;
                            this._certificates.update(c);
                        }
                    }
                    // Update any certificates signed by this one
                    if (type != CertTypes_1.CertTypes.leaf) {
                        // Update certificates that this one signed
                        let list = yield this._findSigned(c, newRecord.$loki);
                        result.updated = result.updated.concat(list);
                    }
                    // See if we have a private key for this certificate
                    let keys = this._privateKeys.chain().find({ pairId: null }).data();
                    for (let i in keys) {
                        if (WebServer._isKeyPair(c, keys[i].n, keys[i].e)) {
                            logger.info('Found private key for ' + name);
                            yield (0, promises_1.rename)(this._getKeysDir(WebServer._getKeyFilenameFromRow(keys[i])), this._getKeysDir(WebServer._getKeyFilename(name + '_key', keys[i].$loki)));
                            keys[i].name = name + '_key';
                            keys[i].pairId = newRecord.$loki;
                            this._privateKeys.update(keys[i]);
                            result.updated.push({ type: CertTypes_1.CertTypes.key, id: keys[i].$loki });
                            newRecord.keyId = keys[i].$loki;
                            this._certificates.update(newRecord);
                            break;
                        }
                    }
                    // This guarantees a unique filename
                    let newName = WebServer._getCertificateFilenameFromRow(newRecord);
                    yield (0, promises_1.writeFile)(this._getCertificatesDir(newName), input.pemString, { encoding: 'utf8' });
                    logger.info(`Written file ${newName}`);
                    resolve(result);
                }
                catch (err) {
                    logger.error(err.message);
                    if (!err.status) {
                        err.status = 500;
                    }
                    reject(err);
                }
            }));
        });
    }
    /**
     * Returns details of the certificate for display on the client browser.
     *
     * @param c Certificate row of the certificate requested
     * @returns The useful fields from the certificate row
     */
    _getCertificateBrief(c) {
        var _a;
        let c2 = null;
        if (c.signedById != null) {
            c2 = this._certificates.findOne({ $loki: c.signedById });
            if (c2 == null) {
                logger.warn(`Signed by certificate missing for ${c.name}`);
            }
        }
        // let k = this._privateKeys.findOne({ pairId: c.$loki });
        let s = this._certificates.find({ signedById: c.$loki }).map((r) => r.$loki);
        return {
            id: c.$loki,
            certType: CertTypes_1.CertTypes[c.type],
            name: c.subject.CN,
            issuer: c.issuer,
            subject: c.subject,
            validFrom: c.notBefore,
            validTo: c.notAfter,
            serialNumber: c.serialNumber == null ? '' : c.serialNumber.match(/.{1,2}/g).join(':'),
            signer: c2 ? c2.subject.CN : null,
            signerId: c2 ? c2.$loki : null,
            keyId: c.keyId,
            fingerprint: c.fingerprint,
            fingerprint256: c.fingerprint256,
            signed: s,
            tags: (_a = c.tags) !== null && _a !== void 0 ? _a : [],
        };
    }
    /**
     * Tries to delete a certificate and breaks all the links it has with other certificates and keys if any.
     *
     * @param c The row of the certificate to delete
     * @returns A synopsis of the database updates made as a result of this deletion
     */
    _tryDeleteCert(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let filename = this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c));
                    if (yield (0, exists_1.exists)(filename)) {
                        yield (0, promises_1.unlink)(filename);
                    }
                    else {
                        logger.error(`Could not find file ${filename}`);
                    }
                    let result = {
                        name: '',
                        added: [],
                        updated: [],
                        deleted: [],
                    };
                    result.deleted.push({ type: c.type, id: c.$loki });
                    let key = this._privateKeys.findOne({ $loki: c.keyId });
                    if (key) {
                        key.pairId = null;
                        key.pairCN = null;
                        let unknownName = WebServer._getKeyFilename('unknown_key', key.$loki);
                        yield (0, promises_1.rename)(this._getKeysDir(WebServer._getKeyFilenameFromRow(key)), this._getKeysDir(unknownName));
                        key.name = WebServer._getDisplayName(unknownName);
                        this._privateKeys.update(key);
                        result.updated.push({ type: CertTypes_1.CertTypes.key, id: key.$loki });
                    }
                    this._certificates.chain().find({ signedById: c.$loki }).update((cert) => {
                        if (c.$loki != cert.$loki) {
                            cert.signedById = null;
                            result.updated.push({ type: cert.type, id: cert.$loki });
                        }
                    });
                    this._certificates.remove(c);
                    resolve(result);
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Tries to add the key specified by the pem file to the database and file store.
     * If a certificate pair is found then the certificate row will be updated to show
     * that the key pair is also in the system.
     *
     * @param filename - The path to the file containing the key's pem
     * @param password - Optional password for encrypted keys
     *
     * @returns OperationResultEx2 promise containing updated entries
     */
    _tryAddKey(input) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                try {
                    if (!input.pemString) {
                        logger.info(`Trying to add ${path_1.default.basename(input.filename)}`);
                        if (!(yield (0, exists_1.exists)(input.filename))) {
                            reject(new CertError_1.CertError(404, `${path_1.default.basename(input.filename)} does not exist`));
                        }
                        input.pemString = yield (0, promises_1.readFile)(input.filename, { encoding: 'utf8' });
                    }
                    let result = {
                        name: '',
                        added: [],
                        updated: [],
                        deleted: [],
                    };
                    let k;
                    let msg = node_forge_1.pem.decode(input.pemString)[0];
                    let encrypted = false;
                    if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                        if (!input.password) {
                            logger.warn(`Encrypted key requires password`);
                            return reject(new CertError_1.CertError(400, 'Password is required for key ' + ((_a = input.filename) !== null && _a !== void 0 ? _a : 'no name')));
                        }
                        k = node_forge_1.pki.decryptRsaPrivateKey(input.pemString, input.password);
                        encrypted = true;
                    }
                    else {
                        k = node_forge_1.pki.privateKeyFromPem(input.pemString);
                    }
                    let kRow = { e: k.e, n: k.n, pairId: null, pairCN: null, name: null, type: CertTypes_1.CertTypes.key, encrypted: encrypted };
                    let keys = this._privateKeys.find();
                    let publicKey = node_forge_1.pki.setRsaPublicKey(k.n, k.e);
                    // See if we already have this key
                    for (let i = 0; i < keys.length; i++) {
                        if (WebServer._isIdenticalKey(node_forge_1.pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                            reject(new CertError_1.CertError(409, `Key already present: ${keys[i].name}`));
                        }
                    }
                    // See if this is the key pair for a certificate
                    let certs = this._certificates.find({ keyId: null });
                    let newFile;
                    let certIndex;
                    for (certIndex = 0; certIndex < certs.length; certIndex++) {
                        if (WebServer._isKeyPair(yield this._pkiCertFromRow(certs[certIndex]), k.n, k.e)) {
                            kRow.pairId = certs[certIndex].$loki;
                            kRow.pairCN = certs[certIndex].subject.CN;
                            newFile = certs[certIndex].name + '_key';
                            break;
                        }
                    }
                    // Generate a file name for a key without a certificate
                    if (kRow.pairId == null) {
                        newFile = 'unknown_key';
                        result.name = newFile;
                    }
                    else {
                        result.name = kRow.pairCN + '_key';
                    }
                    kRow.name = newFile;
                    let newRecord = (this._privateKeys.insert(kRow));
                    result.added.push({ type: CertTypes_1.CertTypes.key, id: newRecord.$loki });
                    // Update certificate that key pair
                    if (certIndex < certs.length) {
                        certs[certIndex].keyId = newRecord.$loki;
                        this._certificates.update(certs[certIndex]);
                        result.updated.push({ type: certs[certIndex].type, id: certs[certIndex].$loki });
                    }
                    let newName = WebServer._getKeyFilenameFromRow(newRecord);
                    yield (0, promises_1.writeFile)(this._getKeysDir(newName), input.pemString, { encoding: 'utf8' });
                    logger.info(`Written file ${newName}`);
                    resolve(result);
                }
                catch (err) {
                    logger.error(err.message);
                    if (!err.status) {
                        err.status = 500;
                    }
                    reject(err);
                }
            }));
        });
    }
    /**
     * Returns enough information about a key to build the summary on the client browser.
     *
     * @param r The key row from the database
     * @returns A summary of the database row
     */
    _getKeyBrief(r) {
        return {
            id: r.$loki,
            name: r.name,
            certPair: (r.pairId == null) ? 'Not present' : r.name.substring(0, r.name.length - 4),
            encrypted: r.encrypted,
        };
    }
    /**
     * Deletes a key's pem file and removes it from the database. If this key has a certificate pair that the certificate will be
     * updated to show that it no longer has its key pair in the system.
     *
     * @param k Key to delete
     * @returns Summary of modifications to the database
     */
    _tryDeleteKey(k) {
        return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            try {
                let result = { name: '', added: [], updated: [], deleted: [] };
                let filename = this._getKeysDir(WebServer._getKeyFilenameFromRow(k));
                if (yield (0, exists_1.exists)(filename)) {
                    yield (0, promises_1.unlink)(filename);
                }
                else {
                    logger.error(`Could not find file ${filename}`);
                }
                if (k.pairId) {
                    let cert = this._certificates.findOne({ $loki: k.pairId });
                    if (!cert) {
                        logger.warn(`Could not find certificate with id ${k.pairId}`);
                    }
                    else {
                        cert.keyId = null;
                        this._certificates.update(cert);
                        result.updated.push({ type: cert.type, id: cert.$loki });
                    }
                }
                result.deleted.push({ type: CertTypes_1.CertTypes.key, id: k.$loki });
                this._privateKeys.remove(k);
                resolve(result);
            }
            catch (err) {
                reject(err);
            }
        }));
    }
    /**
     * Takes the certificate's pem string and concatenates the parent certificate's pem string
     * until it reaches the self signed certificate at the top of the chain
     *
     * @param c Certificate at the bottom of the certificate chain
     * @returns Certificate chain
     */
    _getChain(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let file = '';
                    file = yield (0, promises_1.readFile)(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), { encoding: 'utf8' });
                    while (c.signedById != c.$loki) {
                        if (c.signedById === null) {
                            return reject(new CertError_1.CertError(404, 'Certificate chain is incomplete'));
                        }
                        c = this._certificates.findOne({ $loki: c.signedById });
                        file += yield (0, promises_1.readFile)(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), { encoding: 'utf8' });
                    }
                    resolve(file);
                }
                catch (err) {
                    reject(new CertError_1.CertError(500, err.message));
                }
            }));
        });
    }
    /**
     * Takes a filename of a certificate and returns the fully qualified name
     *
     * @param filename The filename of the certificate
     * @returns The fully qualified name of that certificate
     */
    _getCertificatesDir(filename) {
        return path_1.default.join(this._certificatesPath, filename);
    }
    /**
     * Takes a filename of a key and returns the fully qualified name
     *
     * @param filename The filename of the key
     * @returns The fully qualifed name
     */
    _getKeysDir(filename) {
        return path_1.default.join(this._privatekeysPath, filename);
    }
    /**
     * Search for a certificate that signed this certificate
     * @param certificate Certificate for which to search for a signer
     * @returns The certificate row of the certificate that signed the passed certificate
     */
    _findSigner(certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
                let i;
                let caList = this._certificates.find({ 'type': { '$in': [CertTypes_1.CertTypes.root, CertTypes_1.CertTypes.intermediate] } });
                for (i = 0; i < caList.length; i++) {
                    try {
                        let c = yield this._pkiCertFromRow((caList[i]));
                        if (c.verify(certificate)) {
                            resolve(caList[i]);
                            break;
                        }
                    }
                    catch (err) {
                        // TODO Handle other errors than verify error
                        if (!err.actualIssuer || !err.expectedIssuer) {
                            logger.debug(`Possible error: ${err.message}`);
                        }
                        // verify should return false but apparently throws an exception - do nothing
                    }
                }
                if (i == caList.length) {
                    resolve(null);
                }
            }));
        });
    }
    /**
     * Find and update any certificates that were signed by the passed certificate
     *
     * @param certificate Certificate used to test all certificates to see if they were signed by this one
     * @param id The row id from the database
     * @returns The results of the modifications to the certificate rows
     */
    _findSigned(certificate, id) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let signeeList = this._certificates.find({ $and: [
                        { signedById: { $eq: null } },
                        { $loki: { $ne: id } },
                        { type: { $in: [CertTypes_1.CertTypes.leaf, CertTypes_1.CertTypes.intermediate] } }
                    ] });
                let retVal = [];
                try {
                    for (const s of signeeList) {
                        let check = yield this._pkiCertFromRow(s);
                        logger.debug(`Checking ${check.subject.getField('CN').value}`);
                        try {
                            if (certificate.verify(check)) {
                                this._certificates.chain().find({ $loki: s.$loki }).update((u) => {
                                    u.signedById = id;
                                });
                                logger.debug(`Marked ${s.name} as signed by ${certificate.subject.getField('CN').name}`);
                                retVal.push({ type: s.type, id: s.$loki });
                            }
                            else {
                                logger.debug(`Did not sign ${check.subject.getField('CN').value}`);
                            }
                        }
                        catch (err) {
                            if (err.message != 'The parent certificate did not issue the given child certificate; the child certificate\'s issuer does not match the parent\'s subject.') {
                                logger.debug('Verify correct error: ' + err.message);
                            }
                            // verify should return false but apparently throws an exception - do nothing except when it is an unexpected error message
                        }
                    }
                    resolve(retVal);
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Broadcasts the updates to the certificates and keys to all of the web clients
     *
     * @param data the collection of operation results
     */
    _broadcast(data) {
        let msg = JSON.stringify(data);
        logger.debug('Updates: ' + msg);
        this._ws.clients.forEach((client) => {
            client.send(msg, (err) => {
                if (err) {
                    logger.error(`Failed to send to client`);
                }
                else {
                    logger.debug('Sent update to client');
                }
            });
        });
    }
    /**
     * Returns the certificate row that is identified by either the id or name. This accepts the body from the web client as input.
     * @param query Should contain either an id member or name member but not both
     * @returns The certificate row referenced by the input
     */
    _resolveCertificateQuery(query) {
        let c;
        if ('name' in query && 'id' in query)
            throw new CertError_1.CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query))
            throw new CertError_1.CertError(400, 'Name or id must be specified');
        let selector = ('name' in query) ? { name: query.name } : { $loki: parseInt(query.id) };
        c = this._certificates.find(selector);
        if (c.length == 0) {
            throw new CertError_1.CertError(404, `No certificate for ${query.id ? 'id' : 'name'} ${Object.values(selector)[0]} found`);
        }
        else if (c.length > 1) {
            throw new CertMultiError_1.CertMultiError(400, `Multiple certificates match the name ${Object.values(selector)[0]} - use id instead`, c.map((l) => l.$loki));
        }
        return c[0];
    }
    /**
     * Update the certificate row that is identified by either the id or name. This accepts the body from the web client as input.
     *
     * @param query Should contain either an id member or name member but not both
     * @param updater A void function that accepts a certificate row and modifies the contents
     * @returns The results of the operation with the row id of the updated certificate
     */
    _resolveCertificateUpdate(query, updater) {
        if ('name' in query && 'id' in query)
            throw new CertError_1.CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query))
            throw new CertError_1.CertError(400, 'Name or id must be specified');
        let selector = ('name' in query) ? { name: query.name } : { $loki: parseInt(query.id) };
        let c = this._certificates.chain().find(selector);
        if (c.count() == 0) {
            throw new CertError_1.CertError(404, `No certificate for ${query.id ? 'id' : 'name'} ${Object.values(selector)[0]} found`);
        }
        else if (c.count() > 1) {
            throw new CertError_1.CertError(400, `Multiple certificates match the name ${Object.values(selector)[0]} - use id instead`);
        }
        let result = { name: null, added: [], updated: [], deleted: [] };
        let cd = c.data()[0];
        result.name = cd.subject.CN;
        result.updated.push({ type: cd.type, id: cd.$loki });
        c.update(updater);
        return result;
    }
    /**
     * Returns the key row that is identified by either the id or name. This accepts the body from the web client as input.
     *
     * @param query Should contain either an id member or name member but not both
     * @returns The key row referenced by the input
     */
    _resolveKeyQuery(query) {
        let k;
        let selector;
        if (query.name && query.id)
            throw new CertError_1.CertError(422, 'Name and id are mutually exclusive');
        if (!query.name && !query.id)
            throw new CertError_1.CertError(400, 'Name or id must be specified');
        if (query.name) {
            selector = { name: query.name };
        }
        else if (query.id) {
            let id = parseInt(query.id);
            if (isNaN(id))
                throw new CertError_1.CertError(400, 'Specified id is not numeric');
            selector = { $loki: id };
        }
        k = this._privateKeys.find(selector);
        if (k.length == 0) {
            throw new CertError_1.CertError(404, `No key for ${JSON.stringify(query)} found`);
        }
        else if (k.length > 1) {
            throw new CertError_1.CertError(400, `Multiple keys match the CN ${JSON.stringify(query)} - use id instead`);
        }
        return k[0];
    }
    /**
     * Returns the decoded pem file referenced by the certificate row
     *
     * @param c Certificate row
     * @returns A pki.Certificate constructed from the certificate's pem file
     */
    _pkiCertFromRow(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let filename = this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c));
                    resolve(node_forge_1.pki.certificateFromPem(yield (0, promises_1.readFile)(filename, { encoding: 'utf8' })));
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Returns the decoded pem file referenced by the key row
     *
     * @param k Key row
     * @param password Optional password if the key is encrypted
     * @returns A pki.PrivateKey constructed from the key's pem file
     */
    _pkiKeyFromRow(k, password) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let filename = this._getKeysDir(WebServer._getKeyFilenameFromRow(k));
                    let p = yield (0, promises_1.readFile)(filename, { encoding: 'utf8' });
                    let msg = node_forge_1.pem.decode(p)[0];
                    if (msg.type.startsWith('ENCRYPTED')) {
                        if (password) {
                            resolve(node_forge_1.pki.decryptRsaPrivateKey(p, password));
                        }
                        else {
                            throw new CertError_1.CertError(400, 'No password provided for encrypted key');
                        }
                    }
                    else {
                        resolve(node_forge_1.pki.privateKeyFromPem(p));
                    }
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * This function is used to update the database when breaking changes are made.
     */
    _databaseFixUp() {
        return __awaiter(this, void 0, void 0, function* () {
            // First check that the database is a version that can be operated upon by the code.
            if (this._currentVersion < 4) {
                console.error(`Database version ${this._currentVersion} is not supported by the release - try installing the previous minor version`);
                process.exit(4);
            }
            this._certificates.find({ $and: [{ signedById: null }, { type: 1 }] }).forEach(r => logger.warn(`Bad signed (${r.$loki}): ${r.subject.CN} - fixing`));
            this._certificates.chain().find({ $and: [{ signedById: null }, { type: 1 }] }).update((r) => r.signedById = r.$loki);
            // Check that the database is an older version that needs to be modified
            logger.info('Database is a supported version for this release');
        });
    }
    static _validateCertificateInput(type, bodyIn) {
        var _a, _b;
        // FUTURE Needs a mechanism to force parts of the RDA sequence to be omitted
        try {
            if (typeof bodyIn !== 'object') {
                throw new CertError_1.CertError(400, 'Bad POST data format - use Content-type: application/json');
            }
            let body = bodyIn;
            let result = {
                validFrom: body.validFrom ? new Date(body.validFrom) : new Date(),
                validTo: new Date(body.validTo),
                signer: (_a = body.signer) !== null && _a !== void 0 ? _a : null,
                password: (_b = body.password) !== null && _b !== void 0 ? _b : null,
                subject: {
                    C: body.country ? body.country : null,
                    ST: body.state ? body.state : null,
                    L: body.location ? body.location : null,
                    O: body.organization ? body.organization : null,
                    OU: body.unit ? body.unit : null,
                    CN: body.commonName ? body.commonName : null
                },
                san: {
                    domains: [],
                    IPs: [],
                }
            };
            let errString = [];
            if (!result.subject.CN)
                errString.push('Common name is required');
            if (!result.validTo)
                errString.push('Valid to is required');
            if (type != CertTypes_1.CertTypes.root && !body.signer)
                errString.push('Signing certificate is required');
            if (isNaN(result.validTo.valueOf()))
                errString.push('Valid to is invalid');
            if (body.validFrom && isNaN(result.validFrom.valueOf()))
                errString.push('Valid from is invalid');
            if (result.subject.C != null && result.subject.C.length != 2)
                errString.push('Country code must be omitted or have two characters');
            let rc = WebServer._isValidRNASequence([result.subject.C, result.subject.ST, result.subject.L, result.subject.O, result.subject.OU, result.subject.CN]);
            if (!rc.valid)
                errString.push(rc.message);
            if (errString.length > 0) {
                throw new CertError_1.CertError(500, errString.join(';'));
            }
            if (type == CertTypes_1.CertTypes.leaf) {
                result.san.domains.push(body.commonName);
            }
            if (type != CertTypes_1.CertTypes.root && body.SANArray) {
                let SANArray = Array.isArray(body.SANArray) ? body.SANArray : [body.SANArray];
                let domains = SANArray.filter((entry) => entry.startsWith('DNS:')).map((entry) => entry.split(' ')[1]);
                let ips = SANArray.filter((entry) => entry.startsWith('IP:')).map((entry) => entry.split(' ')[1]);
                if (domains.length > 0)
                    result.san.domains = result.san.domains.concat(domains);
                if (ips.length > 0)
                    result.san.IPs = ips;
            }
            return result;
        }
        catch (err) {
            throw new CertError_1.CertError(500, err.message);
        }
    }
    /**
     * Attempts to guess the client OS from the user agent string
     *
     * @param userAgent User agent string
     * @returns The enum of the OS it thinks is on the client
     */
    static _guessOs(userAgent) {
        if (userAgent === null || userAgent === '')
            return userAgentOS_1.userAgentOS.UNKNOWN;
        let ua = userAgent.toLowerCase();
        if (ua.includes('powershell'))
            return userAgentOS_1.userAgentOS.WINDOWS; // Powershell will always be treated as Windows
        if (ua.includes('windows'))
            return userAgentOS_1.userAgentOS.WINDOWS;
        if (ua.includes('linux'))
            return userAgentOS_1.userAgentOS.LINUX;
        if (ua.includes('curl'))
            return userAgentOS_1.userAgentOS.LINUX; // Best guess
        if (ua.includes('wget'))
            return userAgentOS_1.userAgentOS.LINUX; // Another best guess
        if (ua.includes('mac'))
            return userAgentOS_1.userAgentOS.MAC;
        if (ua.includes('x11'))
            return userAgentOS_1.userAgentOS.LINUX;
        if (ua.includes('iphone'))
            return userAgentOS_1.userAgentOS.IPHONE;
        if (ua.includes('android'))
            return userAgentOS_1.userAgentOS.ANDROID;
        return userAgentOS_1.userAgentOS.UNKNOWN;
    }
    /**
     * Validates RNA strings to ensure they consist only of characters allowed in those strings. The node-forge package does not enforce this.
     *
     * @param rnas Array of RNA values for validation
     * @returns {{valid: boolean, message?: string}} valid: true if all are valid otherwise valid: false, message: error message
     */
    static _isValidRNASequence(rnas) {
        for (let r in rnas) {
            if (!/^[a-z A-Z 0-9'\=\(\)\+\,\-\.\/\:\?]*$/.test(rnas[r])) {
                return { valid: false, message: 'Subject contains an invalid character' };
            }
        }
        return { valid: true };
    }
    /**
     * Tests a certificate and key to determine if they are a pair
     *
     * @param cert Certificate in node-forge pki format
     * @param keyn Key n big integer
     * @param keye Key e big integer
     * @returns true if this is the key paired with the certificate
     */
    static _isKeyPair(cert, keyn, keye) {
        let publicKey = node_forge_1.pki.setRsaPublicKey(keyn, keye);
        let certPublicKey = cert.publicKey;
        return this._isIdenticalKey(publicKey, certPublicKey);
    }
    /**
     * Compares to keys for equality
     *
     * @param leftKey First key to compare
     * @param rightKey Second key to compare
     * @returns true if the keys are identical
     */
    static _isIdenticalKey(leftKey, rightKey) {
        if (leftKey.n.data.length != rightKey.n.data.length) {
            return false;
        }
        for (let i = 0; i < leftKey.n.data.length; i++) {
            if (leftKey.n.data[i] != rightKey.n.data[i])
                return false;
        }
        return true;
    }
    /**
     * Determines the filename of a certificate from the database record
     *
     * @param c Certificate's database record
     * @returns Filename in the form of name_identity.pem
     */
    static _getCertificateFilenameFromRow(c) {
        return `${c.name}_${c.$loki}.pem`;
    }
    /**
     * Determines the filename of a key from the database record
     *
     * @param k key's database record
     * @returns Filename in the form of name_identity.pem
     */
    static _getKeyFilenameFromRow(k) {
        return WebServer._getKeyFilename(k.name, k.$loki);
    }
    /**
     * Determines the filename for a key
     *
     * @param name Name in the key record
     * @param $loki Identity in the key record
     * @returns Filename in the form of name_identity.pem
     */
    static _getKeyFilename(name, $loki) {
        return `${name}_${$loki}.pem`;
    }
    /**
     * Removes the id from the end of the input name
     *
     * @param name Input name
     * @returns Display name
     */
    static _getDisplayName(name) {
        return name.split('_').slice(0, -1).join('_');
    }
    /**
     * Parse the id from the end of the filename
     *
     * @param name Filename of key or certificate
     * @returns  Database id associated with this file
     */
    static _getIdFromFileName(name) {
        return parseInt(path_1.default.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }
    /**
     * Converts certain special characters to an underscore
     *
     * @param name Input string
     * @returns Input with special characters replaced with underscores
     */
    static _sanitizeName(name) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }
    /**
     * Extracts the issuer or subject values and returns them as a CertificateSubject
     *
     * @param s pki.Certificate field
     * @returns Extracted subject elements
     */
    static _getSubject(s) {
        let getValue = (v) => {
            let work = s.getField(v);
            return work ? work.value : null;
        };
        return {
            C: getValue('C'),
            ST: getValue('ST'),
            L: getValue('L'),
            O: getValue('O'),
            OU: getValue('OU'),
            CN: getValue('CN')
        };
    }
    /**
     * Add subject values to pki.CertificateField
     *
     * @param subject Subject fields for the certificate
     * @returns pki.CertificateField with the provided fields
     */
    static _setAttributes(subject) {
        let attributes = [];
        if (subject.C)
            attributes.push({ shortName: 'C', value: subject.C });
        if (subject.ST)
            attributes.push({ shortName: 'ST', value: subject.ST });
        if (subject.L)
            attributes.push({ shortName: 'L', value: subject.L });
        if (subject.O)
            attributes.push({ shortName: 'O', value: subject.O });
        if (subject.OU)
            attributes.push({ shortName: 'OU', value: subject.OU });
        attributes.push({ shortName: 'CN', value: subject.CN });
        return attributes;
    }
    /**
     * Generates a certificate serial number
     *
     * @returns A random number to use as a certificate serial number
     */
    static _getRandomSerialNumber() {
        return WebServer._makeNumberPositive(node_forge_1.util.bytesToHex(node_forge_1.random.getBytesSync(20)));
    }
}
exports.WebServer = WebServer;
WebServer.instance = null;
WebServer._lowestDBVersion = 0;
/**
 * If the passed number is negative it is made positive
 *
 * @param hexString String containing a hexadecimal number
 * @returns Positive version of the input
 */
WebServer._makeNumberPositive = (hexString) => {
    let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);
    if (mostSignificativeHexDigitAsInt < 8)
        return hexString;
    mostSignificativeHexDigitAsInt -= 8;
    return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
};
//# sourceMappingURL=webserver.js.map