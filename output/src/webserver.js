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
// import { exists } from 'node:fs/promises';
const path_1 = __importDefault(require("path"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
//import * as fspromises from 'fs/promises'
const promises_1 = require("fs/promises");
const crypto_1 = __importDefault(require("crypto"));
const node_forge_1 = require("node-forge");
const lokijs_1 = __importStar(require("lokijs"));
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const serve_favicon_1 = __importDefault(require("serve-favicon"));
const ws_1 = __importDefault(require("ws"));
const log4js = __importStar(require("log4js"));
const certificateCache_1 = require("./certificateCache");
const eventWaiter_1 = require("./utility/eventWaiter");
const exists_1 = require("./utility/exists");
const ExtensionBasicConstraints_1 = require("./Extensions/ExtensionBasicConstraints");
const ExtensionKeyUsage_1 = require("./Extensions/ExtensionKeyUsage");
const ExtensionAuthorityKeyIdentifier_1 = require("./Extensions/ExtensionAuthorityKeyIdentifier");
const ExtensionSubjectKeyIdentifier_1 = require("./Extensions/ExtensionSubjectKeyIdentifier");
const ExtensionExtKeyUsage_1 = require("./Extensions/ExtensionExtKeyUsage");
const ExtensionSubjectAltName_1 = require("./Extensions/ExtensionSubjectAltName");
var CertTypes;
(function (CertTypes) {
    CertTypes[CertTypes["cert"] = 0] = "cert";
    CertTypes[CertTypes["root"] = 1] = "root";
    CertTypes[CertTypes["intermediate"] = 2] = "intermediate";
    CertTypes[CertTypes["leaf"] = 3] = "leaf";
    CertTypes[CertTypes["key"] = 4] = "key";
})(CertTypes || (CertTypes = {}));
class CertError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}
const logger = log4js.getLogger();
logger.level = "debug";
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
    constructor(config) {
        this.DB_NAME = 'certs.db';
        this._app = (0, express_1.default)();
        this._ws = new ws_1.default.Server({ noServer: true });
        this._certificate = null;
        this._key = null;
        this._version = 'v' + require('../../package.json').version;
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
        this._certificatesPath = path_1.default.join(this._dataPath, 'certificates');
        this._privatekeysPath = path_1.default.join(this._dataPath, 'privatekeys');
        this._workPath = path_1.default.join(this._dataPath, 'work');
        this._dbPath = path_1.default.join(this._dataPath, 'db');
        if (!(0, node_fs_1.existsSync)(this._dataPath))
            (0, node_fs_1.mkdirSync)(this._dataPath, { recursive: true });
        if (!(0, node_fs_1.existsSync)(this._certificatesPath))
            (0, node_fs_1.mkdirSync)(this._certificatesPath);
        if (!(0, node_fs_1.existsSync)(this._privatekeysPath))
            (0, node_fs_1.mkdirSync)(this._privatekeysPath);
        if (!(0, node_fs_1.existsSync)(this._workPath))
            (0, node_fs_1.mkdirSync)(this._workPath);
        if (!(0, node_fs_1.existsSync)(this._dbPath))
            (0, node_fs_1.mkdirSync)(this._dbPath);
        this._cache = new certificateCache_1.CertificateCache(this._certificatesPath, 10 * 60 * 60);
        this._app.set('views', path_1.default.join(__dirname, '../../web/views'));
        this._app.set('view engine', 'pug');
    }
    start() {
        return __awaiter(this, void 0, void 0, function* () {
            let getCollections = () => {
                if (null == (certificates = db.getCollection('certificates'))) {
                    certificates = db.addCollection('certificates', {});
                }
                if (null == (privateKeys = db.getCollection('privateKeys'))) {
                    privateKeys = db.addCollection('privateKeys', {});
                }
                ew.EventSet();
            };
            try {
                var ew = new eventWaiter_1.EventWaiter();
                var certificates = null;
                var privateKeys = null;
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
                yield this._dbInit();
            }
            catch (err) {
                logger.fatal('Failed to initialize the database: ' + err.message);
                process.exit(4);
            }
            // this._app.use(Express.bodyParser.json());
            this._app.use(express_1.default.urlencoded({ extended: true }));
            this._app.use((0, serve_favicon_1.default)(path_1.default.join(__dirname, "../../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
            this._app.use(express_1.default.text({ type: 'text/plain' }));
            this._app.use(express_1.default.text({ type: 'application/x-www-form-urlencoded' }));
            this._app.use(express_1.default.text({ type: 'application/json' }));
            this._app.use('/scripts', express_1.default.static(path_1.default.join(__dirname, '../../web/scripts')));
            this._app.use('/styles', express_1.default.static(path_1.default.join(__dirname, '../../web/styles')));
            this._app.use('/icons', express_1.default.static(path_1.default.join(__dirname, '../../web/icons')));
            this._app.use('/files', express_1.default.static(path_1.default.join(__dirname, '../../web/files')));
            this._app.use('/images', express_1.default.static(path_1.default.join(__dirname, '../../web/images')));
            // this._app.use('/certificates', Express.static(this._certificatesPath));
            // this._app.use('/keys', Express.static(this._privatekeysPath));
            this._app.use((0, express_fileupload_1.default)());
            this._app.use((req, _res, next) => {
                logger.debug(`${req.method} ${req.url}`);
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
            this._app.post('/createCACert', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/createcacert';
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
            this._app.post('/uploadCert', ((req, res) => {
                // FUTURE Allow multiple files to be submitted
                // FUTURE: Allow chain style files to be submitted
                // FUTURE: Allow der and pfx files to be submitted
                if (!req.files || Object.keys(req.files).length == 0) {
                    return res.status(400).send('No file selected');
                }
                let certfile = req.files.certFile;
                let tempName = path_1.default.join(this._workPath, certfile.name);
                certfile.mv(tempName, (err) => __awaiter(this, void 0, void 0, function* () {
                    var _a;
                    if (err)
                        return res.status(500).send(err);
                    try {
                        let result = yield this._tryAddCertificate(tempName);
                        this._broadcast(result);
                        return res.status(200).json({ message: `Certificate ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
                    }
                    catch (err) {
                        return res.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).send(err.message);
                    }
                }));
            }));
            this._app.delete('/deleteCert', ((request, _response, next) => {
                request.url = '/api/deleteCert';
                next();
            }));
            this._app.get('/certList', (request, _response, next) => {
                request.url = '/api/certList';
                next();
            });
            this._app.get('/certDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                let query = {};
                if (request.query.name)
                    query = { name: request.query.name };
                else if (request.query.id)
                    query = { $loki: parseInt(request.query.id) };
                else
                    return response.status(400).json({ Message: 'Invalid URL query' });
                let c = this._certificates.findOne(query);
                if (c) {
                    let retVal = this._getCertificateBrief(c);
                    response.status(200).json(retVal);
                }
                else {
                    response.status(404).json({ Message: 'Certificate not found' });
                }
            }));
            this._app.post('/uploadKey', ((request, res) => {
                if (!request.files || Object.keys(request.files).length == 0) {
                    return res.status(400).send('No file selected');
                }
                let keyFile = request.files.keyFile;
                if (!keyFile) {
                    throw new CertError(404, 'Key file not found in request');
                }
                let tempName = path_1.default.join(this._workPath, keyFile.name);
                keyFile.mv(tempName, (err) => __awaiter(this, void 0, void 0, function* () {
                    var _a;
                    if (err)
                        return res.status(500).send(err);
                    try {
                        let result = yield this._tryAddKey(tempName, request.query.password);
                        this._broadcast(result);
                        return res.status(200).json({ message: `Key ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
                    }
                    catch (err) {
                        return res.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).send(err.message);
                    }
                }));
            }));
            this._app.delete('/deleteKey', ((request, _response, next) => {
                request.url = '/api/deleteKey';
                next();
            }));
            this._app.get('/keyList', (request, _response, next) => {
                request.url = '/certlist';
                next();
            });
            this._app.get('/keyDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                let query = {};
                if (request.query.name)
                    query = { name: request.query.name };
                else if (request.query.id)
                    query = { $loki: parseInt(request.query.id) };
                else
                    return response.status(400).json({ Message: 'Invalid URL query' });
                let k = this._privateKeys.findOne(query);
                if (k) {
                    let retVal = this._getKeyBrief(k);
                    response.status(200).json(retVal);
                }
                else {
                    response.status(404).json({ Message: 'Key not found' });
                }
            }));
            this._app.post('/api/createCaCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let body = typeof request.body == 'string' ? JSON.parse(request.body) : request.body;
                    let validFrom = body.caValidFrom ? new Date(body.caValidFrom) : new Date();
                    let validTo = body.caValidTo ? new Date(body.caValidTo) : null;
                    let subject = {
                        C: body.caCountry,
                        ST: body.caState,
                        L: body.caLocation,
                        O: body.caOrganization,
                        OU: body.caUnit,
                        CN: body.caCommonName
                    };
                    let errString = '';
                    if (!subject.CN)
                        errString += 'Common name is required</br>\n';
                    if (!validTo)
                        errString += 'Valid to is required\n';
                    if (errString) {
                        return response.status(400).json({ message: errString });
                    }
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._getAttributes(subject);
                    const extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true }),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(privateKey, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newca.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newca-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newca.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newca-key.pem')));
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name} added`, types: [CertTypes[CertTypes.root], CertTypes[CertTypes.key]].join(';') });
                }
                catch (err) {
                    return response.status(500).json({ error: err });
                }
            }));
            this._app.post('/api/createIntermediateCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let body = typeof request.body == 'string' ? JSON.parse(request.body) : request.body;
                    let validFrom = body.intValidFrom ? new Date(body.intValidFrom) : new Date();
                    let validTo = body.intValidTo ? new Date(body.intValidTo) : null;
                    let subject = {
                        C: body.intCountry,
                        ST: body.intState,
                        L: body.intLocation,
                        O: body.intOrganization,
                        OU: body.intUnit,
                        CN: body.intCommonName
                    };
                    let errString = '';
                    if (!subject.CN)
                        errString += 'Common name is required</br>\n';
                    if (!validTo)
                        errString += 'Valid to is required\n';
                    if (!body.intSigner)
                        errString += 'Signing certificate is required';
                    if (errString) {
                        return response.status(400).json({ message: errString });
                    }
                    const cRow = this._certificates.findOne({ name: body.intSigner });
                    const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });
                    if (!cRow) {
                        return response.status(404).json({ message: 'Could not find signing certificate' });
                    }
                    if (!kRow) {
                        return response.status(404).json({ message: 'Could not find signing certificate\'s private key' });
                    }
                    const c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(cRow)), { encoding: 'utf8' }));
                    let k;
                    if (c) {
                        if (body.intPassword) {
                            k = node_forge_1.pki.decryptRsaPrivateKey(yield (0, promises_1.readFile)(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }), body.intPassword);
                        }
                        else {
                            k = node_forge_1.pki.privateKeyFromPem(yield (0, promises_1.readFile)(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }));
                        }
                    }
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._getAttributes(subject);
                    const extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true }),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                        new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Sign with parent certificate's private key
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newint.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newint-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newint.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newint-key.pem')));
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let retTypes = Array.from(new Set(certResult.types.concat(keyResult.types).concat([CertTypes.intermediate]))).map((type) => CertTypes[type]);
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name} added`, types: retTypes.join(';') });
                }
                catch (err) {
                    return response.status(500).json({ message: err.message });
                }
            }));
            this._app.post('/api/createLeafCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let body = typeof request.body == 'string' ? JSON.parse(request.body) : request.body;
                    let validFrom = body.leafValidFrom ? new Date(body.leafValidFrom) : new Date();
                    let validTo = body.leafValidTo ? new Date(body.leafValidTo) : null;
                    let subject = {
                        C: body.leafCountry,
                        ST: body.leafState,
                        L: body.leafLocation,
                        O: body.leafOrganization,
                        OU: body.leafUnit,
                        CN: body.leafCommonName
                    };
                    let errString = '';
                    if (!subject.CN)
                        errString += 'Common name is required</br>\n';
                    if (!validTo)
                        errString += 'Valid to is required\n';
                    if (errString) {
                        return response.status(400).json({ message: errString });
                    }
                    const cRow = this._certificates.findOne({ name: body.leafSigner });
                    const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });
                    if (!cRow || !kRow) {
                        return response.status(500).json({ message: 'Unexpected database corruption - rows missing' });
                    }
                    const c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(cRow)), { encoding: 'utf8' }));
                    let k;
                    if (c) {
                        if (body.leafPassword) {
                            k = node_forge_1.pki.decryptRsaPrivateKey(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }), body.leafPassword);
                        }
                        else {
                            k = node_forge_1.pki.privateKeyFromPem(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }));
                        }
                    }
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = WebServer._getAttributes(subject);
                    let sal = { domains: [subject.CN] };
                    let extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: false }),
                        new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
                        new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                        new ExtensionExtKeyUsage_1.ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true }),
                        new ExtensionSubjectAltName_1.ExtensionSubjectAltName(sal),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = WebServer._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newleaf.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'newleaf-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newleaf.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newleaf-key.pem')));
                    certResult.added = certResult.added.concat(keyResult.added);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let retTypes = Array.from(new Set(certResult.types.concat(keyResult.types).concat([CertTypes.leaf]))).map((type) => CertTypes[type]);
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, types: retTypes.join(';') });
                }
                catch (err) {
                    return response.status(500).json({ message: err.message });
                }
            }));
            this._app.get('/api/certName', (request, response) => __awaiter(this, void 0, void 0, function* () {
                let c = this._certificates.findOne({ $loki: parseInt(request.query.id) });
                if (c) {
                    response.status(200).json({ 'name': c.name });
                }
                else {
                    response.status(404).json({ Message: 'Certificate not found' });
                }
            }));
            this._app.get('/api/keyList', (request, _response, next) => {
                request.url = '/api/certList?type=key';
                next();
            });
            this._app.get('/api/certList', (request, response) => {
                let type = CertTypes[request.query.type];
                if (type == undefined) {
                    response.status(404).send(`Directory ${request.query.type} not found`);
                }
                else {
                    let retVal = {};
                    if (type != CertTypes.key) {
                        retVal['files'] = this._certificates.chain().find({ type: type }).simplesort('name').data().map((entry) => {
                            return { name: entry.name, type: CertTypes[type].toString(), id: entry.$loki };
                        });
                    }
                    else {
                        retVal['files'] = this._privateKeys.chain().find().simplesort('name').data().map((entry) => {
                            return { name: entry.name, id: 'id_' + type.toString() + '_' + entry.$loki.toString() };
                        });
                    }
                    response.status(200).json(retVal);
                }
            });
            this._app.get('/api/getCertificatePem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                try {
                    if (!request.query.id) {
                        throw new CertError(402, 'Id must be specified');
                    }
                    let c = this._certificates.findOne({ $loki: parseInt(request.query.id) });
                    if (c == null) {
                        throw new CertError(404, 'Certificate does not exist');
                    }
                    // let filename = c.name;
                    response.download(path_1.default.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(c)), c.name, (err) => {
                        if (err) {
                            return response.status(500).json({ error: `Failed to file for ${request.query.id}: ${err.message}` });
                        }
                    });
                }
                catch (err) {
                    logger.error('Certificate download failed: ', err.message);
                    return response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json({ error: err.message });
                }
            }));
            this._app.post('/api/uploadCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                if (!request.body.includes('\n')) {
                    return response.status(400).send('Certificate must be in standard 64 byte line length format - try --data-binary on curl');
                }
                try {
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                    //writeFileSync(path.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                    let result = yield this._tryAddCertificate(path_1.default.join(this._workPath, 'upload.pem'));
                    this._broadcast(result);
                    return response.status(200).json({ message: `Certificate ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    response.status(500).send(err.message);
                }
            }));
            this._app.delete('/api/deleteCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _b;
                try {
                    let options = {};
                    if (request.query.serialNumber)
                        options['serialNumber'] = request.query.serialNumber;
                    else
                        options['name'] = request.query.name;
                    let result = yield this._tryDeleteCert(options);
                    this._broadcast(result);
                    return response.status(200).json({ message: `Certificate ${result.name} deleted`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    return response.status((_b = err.status) !== null && _b !== void 0 ? _b : 500).json(JSON.stringify({ error: err.message }));
                }
            }));
            this._app.get('/api/keyname', (request, response) => __awaiter(this, void 0, void 0, function* () {
                let c = this._privateKeys.findOne({ $loki: parseInt(request.query.id) });
                if (c) {
                    response.status(200).json({ 'name': c.name });
                }
                else {
                    response.status(404).json({ Message: 'Key not found' });
                }
            }));
            this._app.post('/api/uploadKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (typeof request.body != 'string') {
                        return response.status(400).send('Content type must be text/plain');
                    }
                    if (!request.body.includes('\n')) {
                        return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary on curl');
                    }
                    yield (0, promises_1.writeFile)(path_1.default.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                    // writeFileSync(path.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                    let result = yield this._tryAddKey(path_1.default.join(this._workPath, 'upload.key'), request.query.password);
                    this._broadcast(result);
                    return response.status(200).json({ message: `Key ${result.name} added`, type: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    response.status(500).send(err.message);
                }
            }));
            this._app.delete('/api/deleteKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _c;
                try {
                    let options = { name: null };
                    options.name = request.query.name;
                    let result = yield this._tryDeleteKey(options);
                    this._broadcast(result);
                    return response.status(200).json({ message: `Key ${result.name} deleted`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    return response.status((_c = err.status) !== null && _c !== void 0 ? _c : 500).json({ error: err.message });
                }
            }));
            this._app.get('/api/getKeyPem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _d;
                try {
                    if (!request.query.id) {
                        throw new CertError(402, 'Id must be specified');
                    }
                    let k = this._privateKeys.findOne({ $loki: parseInt(request.query.id) });
                    if (k == null) {
                        throw new CertError(404, 'Key does not exist');
                    }
                    // let filename = c.name;
                    response.download(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(k)), k.name, (err) => {
                        if (err) {
                            return response.status(500).json({ error: `Failed to file for ${request.query.id}: ${err.message}` });
                        }
                    });
                }
                catch (err) {
                    logger.error('Key download failed: ', err.message);
                    return response.status((_d = err.status) !== null && _d !== void 0 ? _d : 500).json({ error: err.message });
                }
            }));
            this._app.get('/api/chaindownload', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _e;
                try {
                    if (!(yield (0, exists_1.exists)(path_1.default.join(this._certificatesPath, request.query.name + '.pem')))) {
                        throw new CertError(404, `${request.query.name} not found`);
                    }
                    let filename = yield this._getChain(request.query.name);
                    response.download(filename, request.query.name + '_full_chain.pem', (err) => __awaiter(this, void 0, void 0, function* () {
                        if (err) {
                            return response.status(500).json({ error: `Failed to send chain for ${request.query.name}: ${err.message}` });
                        }
                        yield (0, promises_1.unlink)(filename);
                    }));
                }
                catch (err) {
                    logger.error('Chain download failed: ' + err.message);
                    return response.status((_e = err.status) !== null && _e !== void 0 ? _e : 500).json({ error: err.message });
                }
            }));
            let server;
            if (this._certificate) {
                const options = {
                    cert: this._certificate,
                    key: this._key,
                };
                server = https_1.default.createServer(options, this._app).listen(this._port, '0.0.0.0');
            }
            else {
                server = http_1.default.createServer(this._app).listen(this._port, '0.0.0.0');
            }
            logger.info('Listening on ' + this._port);
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
    _dbInit() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let files;
                    let certRows = this._certificates.chain().simplesort('name').data();
                    certRows.forEach((row) => {
                        if (!fs_1.default.existsSync(path_1.default.join(this._certificatesPath, row.name + '.pem'))) {
                            logger.warn(`Certificate ${row.name} not found - removed`);
                            this._certificates.remove(row);
                            this._certificates.chain().find({ 'serialNumber': row.signedBy }).update((r) => {
                                r.serialNumber = null;
                                logger.warn(`Removed signedBy from ${r.name}`);
                            });
                            this._privateKeys.chain().find({ pairSerial: row.serialNumber }).update((k) => {
                                k.pairSerial = null;
                                logger.warn(`Removed relationship to private key from ${k.name}`);
                            });
                        }
                    });
                    files = fs_1.default.readdirSync(this._certificatesPath);
                    let adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        let cert = this._certificates.findOne({ name: path_1.default.parse(file).name });
                        if (!cert) {
                            try {
                                adding.push(this._tryAddCertificate(path_1.default.join(this._certificatesPath, file)));
                            }
                            catch (err) { }
                        }
                    }));
                    yield Promise.all(adding);
                    // let addresults: string[] = await Promise.all(adding);
                    // logger.debug(addresults.join(';'));
                    let nonRoot = this._certificates.find({ '$and': [{ 'type': { '$ne': CertTypes.root } }, { signedBy: null }] });
                    for (let i = 0; i < nonRoot.length; i++) {
                        let signer = yield this._findSigner(node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(nonRoot[i])), { encoding: 'utf8' })));
                        if (signer != null) {
                            logger.info(`${nonRoot[i].name} is signed by ${signer.name}`);
                            nonRoot[i].signedBy = signer.serialNumber;
                            this._certificates.update(nonRoot[i]);
                        }
                    }
                    let keyRows = this._privateKeys.chain().simplesort('name').data();
                    keyRows.forEach((key) => {
                        if (!(0, node_fs_1.existsSync)(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(key)))) {
                            logger.warn(`Key ${key.name} not found - removed`);
                            this._privateKeys.remove(key);
                        }
                    });
                    files = fs_1.default.readdirSync(this._privatekeysPath);
                    adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        // logger.debug(path.basename(file));
                        let key = this._privateKeys.findOne({ name: path_1.default.parse(file).name });
                        if (!key) {
                            try {
                                adding.push(this._tryAddKey(path_1.default.join(this._privatekeysPath, file)));
                            }
                            catch (err) {
                                logger.debug('WTF');
                            }
                        }
                    }));
                    // addresults = await Promise.all(adding);
                    yield Promise.allSettled(adding);
                    // logger.debug(addresults.join(';'));
                    this._db.saveDatabase((err) => {
                        if (err)
                            reject(err);
                        else
                            resolve();
                    });
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    _tryAddCertificate(filename) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                var _a, _b;
                logger.info(`Trying to add ${path_1.default.basename(filename)}`);
                if (!fs_1.default.existsSync(filename)) {
                    let err = new CertError(404, `${path_1.default.basename(filename)} does not exist`);
                    throw err;
                }
                try {
                    let pemString = yield (0, promises_1.readFile)(filename, { encoding: 'utf8' });
                    let msg = node_forge_1.pem.decode(pemString)[0];
                    logger.debug(`Received ${msg.type}`);
                    if (msg.type != 'CERTIFICATE') {
                        throw new CertError(400, 'Unsupported type ' + msg.type);
                    }
                    let result = { name: '', types: [], added: [], updated: [], deleted: [] };
                    let c = node_forge_1.pki.certificateFromPem(pemString);
                    let signedBy = null;
                    let havePrivateKey = false;
                    // See if we already have this certificate
                    if (this._certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                        throw new CertError(409, `${path_1.default.basename(filename)} serial number ${c.serialNumber} is a duplicate - ignored`);
                    }
                    // See if this is a root, intermiate, or leaf
                    if (c.isIssuer(c)) {
                        result.types.push(CertTypes.root);
                        signedBy = c.serialNumber;
                    }
                    else {
                        let bc = c.getExtension('basicConstraints');
                        if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                            result.types.push(CertTypes.intermediate);
                        }
                        else {
                            result.types.push(CertTypes.leaf);
                        }
                        // See if any existing certificates signed this one
                        let signer = yield this._findSigner(c);
                        if (signer != null) {
                            signedBy = signer.serialNumber;
                        }
                    }
                    if (result.types[0] != CertTypes.leaf) {
                        // Update certificates that this one signed
                        let list = yield this._findSigned(c);
                        result.types = result.types.concat(list.types);
                        result.updated = result.updated.concat(list.updated);
                    }
                    // Generate a filename for the common name
                    let name = WebServer._sanitizeName(c.subject.getField('CN').value);
                    // let name = (c.subject.getField('CN').value).replace(/ /g, '_');
                    result.name = name;
                    // Deduplicate if necessary
                    // if (name + '.pem' != path.basename(filename)) {
                    //     if (await exists(path.join(path.dirname(filename), name + '.pem'))) {
                    //         for (let i = 1; true; i++) {
                    //             if (await exists(path.join(path.dirname(filename), name + '_' + i.toString() + '.pem'))) {
                    //                 name = name + '_' + i.toString();
                    //                 break;
                    //             }
                    //         }
                    //     }
                    // logger.info(`Renamed ${path.basename(filename)} to ${name}.pem`)
                    // await rename(filename, path.join(this._certificatesPath, name + '.pem'));
                    // See if we have private key for this certificate
                    // }
                    // See if we have a private key for this certificate
                    let keys = this._privateKeys.chain().find({ pairSerial: null }).data();
                    for (let i = 0; i < keys.length; i++) {
                        if (WebServer._isSignedBy(c, keys[i].n, keys[i].e)) {
                            logger.info('Found private key for ' + name);
                            havePrivateKey = true;
                            yield (0, promises_1.rename)(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(keys[i])), path_1.default.join(this._privatekeysPath, WebServer._getKeyFilename(name + '_key', keys[i].$loki)));
                            keys[i].name = name + '_key';
                            keys[i].pairSerial = c.serialNumber;
                            this._privateKeys.update(keys[i]);
                            result.types.push(CertTypes.key);
                            result.updated.push({ type: CertTypes.key, id: keys[i].$loki });
                            break;
                        }
                    }
                    logger.info(`Certificate ${name} added`);
                    // This is declared as returning the wrong type hence cast below
                    let newRecord = (this._certificates.insert({
                        name: name,
                        type: result.types[0],
                        serialNumber: c.serialNumber,
                        publicKey: c.publicKey,
                        privateKey: null,
                        signedBy: signedBy,
                        issuer: WebServer._getSubject(c.issuer),
                        subject: WebServer._getSubject(c.subject),
                        notBefore: c.validity.notBefore,
                        notAfter: c.validity.notAfter,
                        havePrivateKey: havePrivateKey,
                        fingerprint: new crypto_1.default.X509Certificate(pemString).fingerprint,
                        fingerprint256: new crypto_1.default.X509Certificate(pemString).fingerprint256,
                    })); // Return value erroneous omits LokiObj
                    // This guarantees a unique filename
                    let newName = WebServer._getCertificateFilenameFromRow(newRecord);
                    logger.info(`Renamed ${path_1.default.basename(filename)} to ${newName}`);
                    yield (0, promises_1.rename)(filename, path_1.default.join(this._certificatesPath, newName));
                    // Loki returns a LokiObj but doesn't declare it
                    // certificatesAdded.push((newRecord as unknown as LokiObj).$loki);
                    // switch (types[0]) {
                    //     case CertTypes.root:
                    //         rootsAdded.push((newRecord as unknown as LokiObj).$loki);
                    //         break;
                    //     case CertTypes.intermediate:
                    //         intermediatesAdded.push((newRecord as unknown as LokiObj).$loki);
                    //         break;
                    //     case CertTypes.leaf:
                    //         leavesAdded.push((newRecord as unknown as LokiObj).$loki);
                    //         break;
                    //     default:
                    //         break;
                    // }
                    result.added.push({ type: result.types[0], id: newRecord.$loki });
                    result.types = (Array.from(new Set(result.types)));
                    // result = { 
                    //     name: name, 
                    //     types: (Array.from(new Set(result.types))),
                    //     roots: {added: rootsAdded, updated: rootsUpdated },
                    //     intermediates: {added: intermediatesAdded, updated: intermediatesUpdated},
                    //     leaves: {added: leavesAdded, updated: leavesUpdated },
                    //     keys: { updated: keysUpdated } };
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
    _getCertificateBrief(r) {
        let signer = null;
        if (r.signedBy != null) {
            let s = this._certificates.findOne({ serialNumber: r.signedBy });
            if (s != null)
                signer = s.name;
            else
                logger.warn(`Signed by certificate missing for ${r.name}`);
        }
        let key = this._privateKeys.findOne({ pairSerial: r.serialNumber });
        return {
            id: r.$loki,
            certType: CertTypes[r.type],
            name: r.name,
            issuer: r.issuer,
            subject: r.subject,
            validFrom: r.notBefore,
            validTo: r.notAfter,
            serialNumber: r.serialNumber == null ? '' : r.serialNumber.match(/.{1,2}/g).join(':'),
            signer: signer,
            keyPresent: key != null ? 'yes' : 'no',
            fingerprint: r.fingerprint,
            fingerprint256: r.fingerprint256,
        };
    }
    _tryDeleteCert(options) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                // TODO: Add try block
                let cert = this._certificates.findOne(options.serialNumber ? { serialNumber: options.serialNumber } : { name: options.name });
                if (!cert) {
                    reject(new CertError(404, `Unable to find certificate with ${options.serialNumber ? 'serial number' : 'name'} ${(_a = options.serialNumber) !== null && _a !== void 0 ? _a : options.name}`));
                }
                let filename = path_1.default.join(this._certificatesPath, cert.name + '.pem');
                if (yield (0, exists_1.exists)(filename)) {
                    yield (0, promises_1.unlink)(filename);
                }
                let result = {
                    name: '',
                    types: [],
                    added: [],
                    updated: [],
                    deleted: [],
                };
                // let certTypes: CertTypes[] = [];
                // let keysupdated: number[] = [];
                result.types.push(cert.type);
                result.deleted.push({ type: cert.type, id: cert.$loki });
                let key = this._privateKeys.findOne({ pairSerial: cert.serialNumber });
                if (key) {
                    key.pairSerial = null;
                    let unknownName = WebServer._getKeyFilename('unknown_key', key.$loki);
                    yield (0, promises_1.rename)(path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(key)), path_1.default.join(this._privatekeysPath, unknownName));
                    key.name = WebServer._getDisplayName(unknownName);
                    this._privateKeys.update(key);
                    result.types.push(CertTypes.key);
                    result.updated.push({ type: CertTypes.key, id: key.$loki });
                }
                this._certificates.chain().find({ signedBy: cert.serialNumber }).update((c) => {
                    if (cert.$loki != c.$loki) {
                        c.signedBy = null;
                        result.types.push(c.type);
                        result.updated.push({ type: c.type, id: c.$loki });
                    }
                });
                // let signed = this._certificates.find({ signedBy: cert.serialNumber });
                // for (let i = 0; i < signed.length; i++) {
                //     result.types.push(signed[i].type);
                //     result.updated.push({ type: signed[i].type, id: signed[i].$loki });
                //     signed[i]
                // }
                this._certificates.remove(cert);
                resolve(result);
            }));
        });
    }
    _tryAddKey(filename, password) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                logger.info(`Trying to add ${path_1.default.basename(filename)}`);
                if (!(yield (0, exists_1.exists)(filename))) {
                    reject(new CertError(404, `${path_1.default.basename(filename)} does not exist`));
                }
                try {
                    let result = {
                        name: '',
                        types: [],
                        added: [],
                        updated: [],
                        deleted: [],
                    };
                    let k;
                    let kpem = yield (0, promises_1.readFile)(filename, { encoding: 'utf8' });
                    let msg = node_forge_1.pem.decode(kpem)[0];
                    let encrypted = false;
                    if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                        if (!password) {
                            logger.warn(`Cannot add ${filename} - no pasword for encrypted key`);
                            return reject(new CertError(400, 'Password is required for key ' + filename));
                        }
                        k = node_forge_1.pki.decryptRsaPrivateKey(kpem, password);
                        encrypted = true;
                    }
                    else {
                        k = node_forge_1.pki.privateKeyFromPem(kpem);
                    }
                    let krow = { e: k.e, n: k.n, pairSerial: null, name: null, type: CertTypes.key, encrypted: encrypted };
                    let keys = this._privateKeys.find();
                    let publicKey = node_forge_1.pki.setRsaPublicKey(k.n, k.e);
                    // See if we already have this key
                    for (let i = 0; i < keys.length; i++) {
                        if (WebServer._isIdenticalKey(node_forge_1.pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                            reject(new CertError(409, `Key already present: ${keys[i].name}`));
                        }
                    }
                    // See if this is the key pair for a certificate
                    let certs = this._certificates.find();
                    let newfile = 'unknown_key_';
                    // let types: CertTypes[] = [CertTypes.key];
                    for (let i = 0; i < certs.length; i++) {
                        if (WebServer._isSignedBy(yield this._cache.getCertificate(WebServer._getCertificateFilenameFromRow(certs[i])), k.n, k.e)) {
                            krow.pairSerial = certs[i].serialNumber;
                            result.types.push(certs[i].type);
                            result.updated.push({ type: certs[i].type, id: certs[i].$loki });
                            newfile = certs[i].name + '_key';
                            break;
                        }
                    }
                    // Generate a file name for a key without a certificate
                    if (krow.pairSerial == null) {
                        newfile = 'unknown_key';
                    }
                    result.name = newfile;
                    krow.name = newfile;
                    let newRecord = (this._privateKeys.insert(krow));
                    result.added.push({ type: CertTypes.key, id: newRecord.$loki });
                    yield (0, promises_1.rename)(filename, path_1.default.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(newRecord)));
                    logger.info(`Renamed ${path_1.default.basename(filename)} to ${newfile}.pem`);
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
    _getKeyBrief(r) {
        return {
            id: r.$loki,
            name: r.name,
            certPair: (r.pairSerial == null) ? 'Not present' : r.name.substring(0, r.name.length - 4),
            encrypted: r.encrypted,
        };
    }
    _tryDeleteKey(options) {
        return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            let result = { types: [CertTypes.key], name: '', added: [], updated: [], deleted: [] };
            let key = this._privateKeys.findOne({ name: options.name });
            if (!key) {
                reject(new CertError(404, `Unable to find key with name ${options.name}`));
            }
            let filename = path_1.default.join(this._privatekeysPath, key.name + '.pem');
            if (yield (0, exists_1.exists)(filename)) {
                yield (0, promises_1.unlink)(filename);
            }
            // let certTypes: CertTypes[] = [CertTypes.key];
            // let certificatesupdated: number[] = [];
            if (key.pairSerial) {
                let cert = this._certificates.findOne({ serialNumber: key.pairSerial });
                if (!cert) {
                    logger.warn(`Could not find certificate with serial number ${key.pairSerial}`);
                }
                else {
                    cert.havePrivateKey = false;
                    this._certificates.update(cert);
                    result.types.push(cert.type);
                    result.updated.push({ type: cert.type, id: cert.$loki });
                    // certificatesupdated.push(cert.$loki);
                }
            }
            result.deleted.push({ type: CertTypes.key, id: key.$loki });
            this._privateKeys.remove(key);
            resolve(result);
        }));
    }
    _getChain(certName) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let newFile = path_1.default.join(this._workPath, 'temp_');
                    let i = 0;
                    while (yield (0, exists_1.exists)(newFile + i.toString())) {
                        i++;
                    }
                    newFile += i.toString();
                    yield (0, promises_1.copyFile)(path_1.default.join(this._certificatesPath, certName + '.pem'), newFile);
                    let c = (this._certificates.findOne({ name: certName }));
                    while (c.serialNumber != c.signedBy) {
                        c = this._certificates.findOne({ serialNumber: c.signedBy });
                        yield (0, promises_1.appendFile)(newFile, yield (0, promises_1.readFile)(path_1.default.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(c))));
                    }
                    resolve(newFile);
                }
                catch (err) {
                    reject(new CertError(500, err.message));
                }
            }));
        });
    }
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
    // private async _getUnpairedKeyName(): Promise<string> {
    //     return new Promise(async (resolve, _reject) => {
    //         let newname = 'unknown_key_';
    //         for (let i = 0; true; i++) {
    //             if (!await exists(path.join(this._privatekeysPath, newname + i.toString() + '.pem'))) {
    //                 resolve(newname + i.toString());
    //             }
    //         }
    //     });
    // }
    _findSigner(certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
                let caList = this._certificates.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
                for (let i = 0; i < caList.length; i++) {
                    try {
                        // TODO: Deprecate cache
                        let c = yield this._cache.getCertificate(WebServer._getCertificateFilenameFromRow(caList[i]));
                        if (c.verify(certificate)) {
                            resolve(caList[i]);
                        }
                    }
                    catch (_err) {
                        // logger.debug('Not ' + caList[i].name);
                        // verify should return false but apparently throws an exception - do nothing
                    }
                }
                resolve(null);
            }));
        });
    }
    _findSigned(certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let signeeList = this._certificates.find({ 'type': { '$in': [CertTypes.leaf, CertTypes.intermediate] } });
                let retVal = { types: [], updated: [] };
                try {
                    signeeList.forEach((s) => __awaiter(this, void 0, void 0, function* () {
                        // TODO: Deprecate cache
                        let check = yield this._cache.getCertificate(WebServer._getCertificateFilenameFromRow(s));
                        try {
                            if (certificate.verify(check)) {
                                // BUG I think there is a better way to do this
                                this._certificates.chain().find({ 'serialNumber': check.serialNumber }).update((u) => {
                                    u.signedBy = certificate.serialNumber;
                                });
                                logger.debug(`Marked ${s.name} as signed by ${certificate.subject.getField('CN').name}`);
                                retVal.types.push(s.type);
                                retVal.updated.push({ type: s.type, id: s.$loki });
                                this._cache.markDirty(s.name);
                            }
                        }
                        catch (_err) {
                            // verify should return false but appearently throws an exception - do nothing
                        }
                    }));
                    resolve(retVal);
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    _broadcast(data) {
        let msg = JSON.stringify(data);
        this._ws.clients.forEach((client) => {
            client.send(msg, (err) => {
                if (err) {
                    logger.error(`Failed to send to client`);
                }
                else {
                    logger.debug('Send update to client');
                }
            });
        });
    }
    static _isSignedBy(cert, keyn, keye) {
        let publicKey = node_forge_1.pki.setRsaPublicKey(keyn, keye);
        let certPublicKey = cert.publicKey;
        return this._isIdenticalKey(publicKey, certPublicKey);
    }
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
    static _getCertificateFilenameFromRow(c) {
        return `${c.name}_${c.$loki}.pem`;
    }
    static _getKeyFilenameFromRow(k) {
        return WebServer._getKeyFilename(k.name, k.$loki);
    }
    static _getKeyFilename(name, $loki) {
        return `${name}_${$loki}.pem`;
    }
    static _getDisplayName(name) {
        return name.split('_').slice(0, -1).join('_');
    }
    static _sanitizeName(name) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }
    static _getAttributes(subject) {
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
    // Generate a random serial number for the Certificate
    static _getRandomSerialNumber() {
        return WebServer._makeNumberPositive(node_forge_1.util.bytesToHex(node_forge_1.random.getBytesSync(20)));
    }
}
exports.WebServer = WebServer;
WebServer.instance = null;
WebServer._makeNumberPositive = (hexString) => {
    let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);
    if (mostSignificativeHexDigitAsInt < 8)
        return hexString;
    mostSignificativeHexDigitAsInt -= 8;
    return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
};
//# sourceMappingURL=webserver.js.map