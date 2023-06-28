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
const node_forge_1 = require("node-forge");
const lokijs_1 = __importStar(require("lokijs"));
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const serve_favicon_1 = __importDefault(require("serve-favicon"));
const log4js = __importStar(require("log4js"));
const certificateCache_1 = require("./certificateCache");
const eventWaiter_1 = require("./utility/eventWaiter");
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
    // private constructor(port: number, dataPath: string) {
    constructor(config) {
        this.DB_NAME = 'certs.db';
        this._app = (0, express_1.default)();
        this._certificate = null;
        this._key = null;
        this._makeNumberPositive = (hexString) => {
            let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);
            if (mostSignificativeHexDigitAsInt < 8)
                return hexString;
            mostSignificativeHexDigitAsInt -= 8;
            return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
        };
        this._config = config;
        this._port = config.port;
        this._dataPath = config.root;
        if (config.certificate || config.key) {
            if (!config.certificate || !config.key) {
                throw new Error('Certificate and key must both be present of neither be present');
            }
            this._certificate = fs_1.default.readFileSync(config.certificate, { encoding: 'utf8' });
            this._key = fs_1.default.readFileSync(config.key, { encoding: 'utf8' });
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
        this._app.set('views', path_1.default.join(__dirname, '../web/views'));
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
            this._app.use((0, serve_favicon_1.default)(path_1.default.join(__dirname, "../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
            this._app.use(express_1.default.text({ type: 'text/plain' }));
            this._app.use(express_1.default.text({ type: 'application/x-www-form-urlencoded' }));
            this._app.use('/scripts', express_1.default.static(path_1.default.join(__dirname, '../web/scripts')));
            this._app.use('/styles', express_1.default.static(path_1.default.join(__dirname, '../web/styles')));
            this._app.use('/icons', express_1.default.static(path_1.default.join(__dirname, '../web/icons')));
            this._app.use('/files', express_1.default.static(path_1.default.join(__dirname, '../web/files')));
            this._app.use('/images', express_1.default.static(path_1.default.join(__dirname, '../web/images')));
            this._app.use('/certificates', express_1.default.static(this._certificatesPath));
            this._app.use('/keys', express_1.default.static(this._privatekeysPath));
            this._app.use((req, _res, next) => {
                logger.debug(`${req.method} ${req.url}`);
                next();
            });
            this._app.use((0, express_fileupload_1.default)());
            this._app.post('/uploadCert', ((req, res) => {
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
            this._app.delete('/deleteKey', ((request, _response, next) => {
                request.url = '/api/deleteKey';
                next();
            }));
            this._app.post('/uploadKey', ((request, res) => {
                if (!request.files || Object.keys(request.files).length == 0) {
                    return res.status(400).send('No file selected');
                }
                let keyFile = request.files.keyfile;
                let tempName = path_1.default.join(this._workPath, keyFile.name);
                keyFile.mv(tempName, (err) => __awaiter(this, void 0, void 0, function* () {
                    var _a;
                    if (err)
                        return res.status(500).send(err);
                    try {
                        let result = yield this._tryAddKey(tempName, request.query.password);
                        return res.status(200).json({ message: `Key ${result.name} added`, type: result.types.map((t) => CertTypes[t]).join(';') });
                    }
                    catch (err) {
                        return res.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).send(err.message);
                    }
                }));
            }));
            this._app.get("/", (_request, response) => {
                response.render('index', {
                    title: 'Certificates Management Home',
                    C: this._config.C,
                    ST: this._config.ST,
                    L: this._config.L,
                    O: this._config.O,
                    OU: this._config.OU,
                });
            });
            this._app.get("/certlist", (request, response) => {
                let type = CertTypes[request.query.type];
                if (type == undefined) {
                    response.status(404).send(`Directory ${request.query.type} not found`);
                }
                else {
                    let retVal = {};
                    if (type != CertTypes.key) {
                        retVal['files'] = this._certificates.chain().find({ type: type }).simplesort('name').data().map((entry) => {
                            return { name: entry.name, id: 'id_' + entry.$loki.toString() };
                        });
                    }
                    else {
                        retVal['files'] = this._privateKeys.chain().find().simplesort('name').data().map((entry) => {
                            return { name: entry.name, id: 'id_' + entry.$loki.toString() };
                        });
                    }
                    response.status(200).json(retVal);
                }
            });
            this._app.get("/certdetails", (request, response) => __awaiter(this, void 0, void 0, function* () {
                let filename = path_1.default.join(this._certificatesPath, request.query.name + '.pem');
                if (!(0, node_fs_1.existsSync)(filename))
                    response.status(404);
                let c = this._certificates.findOne({ name: request.query.name });
                if (c) {
                    let retVal = this._getCertificateBrief(c);
                    response.status(200).json(retVal);
                }
                else {
                    response.status(500).send('This should not happen');
                }
            }));
            this._app.get("/keydetails", (request, response) => __awaiter(this, void 0, void 0, function* () {
                let filename = path_1.default.join(this._privatekeysPath, request.query.name + '.pem');
                if (!(0, node_fs_1.existsSync)(filename))
                    response.status(404);
                let k = this._privateKeys.findOne({ name: request.query.name });
                if (k) {
                    let retVal = this._getKeyBrief(k);
                    response.status(200).json(retVal);
                }
                else {
                    response.status(500).send('This should not happen');
                }
            }));
            this._app.post('/api/uploadCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                if (!request.body.includes('\n')) {
                    return response.status(400).send('Certificate must be in standard 64 byte line length format - try --data-binary on curl');
                }
                try {
                    (0, node_fs_1.writeFileSync)(path_1.default.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                    let result = yield this._tryAddCertificate(path_1.default.join(this._workPath, 'upload.pem'));
                    return response.status(200).json({ message: `Certificate ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    response.status(500).send(err.message);
                }
            }));
            this._app.post('/api/uploadKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                if (!request.body.includes('\n')) {
                    return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary on curl');
                }
                try {
                    (0, node_fs_1.writeFileSync)(path_1.default.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                    let result = yield this._tryAddKey(path_1.default.join(this._workPath, 'upload.key'), request.query.password);
                    return response.status(200).json({ message: `Key ${result.name} added`, type: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    response.status(500).send(err.message);
                }
            }));
            this._app.delete('/api/deleteCert', (request, response) => {
                var _a;
                try {
                    let options = {};
                    if (request.query.serialNumber)
                        options['serialNumber'] = request.query.serialNumber;
                    else
                        options['name'] = request.query.name;
                    let result = this._tryDeleteCert(options);
                    return response.status(200).json({ message: `Certificate ${result.name} deleted`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    return response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json(JSON.stringify({ error: err.message }));
                }
            });
            this._app.delete('/api/deleteKey', (request, response) => {
                var _a;
                try {
                    let options = { name: null };
                    options.name = request.query.name;
                    let result = this._tryDeleteKey(options);
                    return response.status(200).json({ message: `Key ${result.name} deleted`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    return response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json({ error: err.message });
                }
            });
            this._app.post('/createCACert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let validFrom = request.body.caValidFrom ? new Date(request.body.caValidFrom) : new Date();
                    let validTo = request.body.caValidTo ? new Date(request.body.caValidTo) : null;
                    let subject = {
                        C: request.body.caCountry,
                        ST: request.body.caState,
                        L: request.body.caLocation,
                        O: request.body.caOrganization,
                        OU: request.body.caUnit,
                        CN: request.body.caCommonName
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
                    const attributes = this._getAttributes(subject);
                    const extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true }),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = this._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(privateKey, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newca.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newca-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newca.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newca-key.pem')));
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, types: [CertTypes[CertTypes.root], CertTypes[CertTypes.key]].join(';') });
                }
                catch (err) {
                    return response.status(500).json({ error: err });
                }
            }));
            this._app.post('/createIntermediateCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let validFrom = request.body.intValidFrom ? new Date(request.body.intValidFrom) : new Date();
                    let validTo = request.body.intValidTo ? new Date(request.body.intValidTo) : null;
                    let subject = {
                        C: request.body.intCountry,
                        ST: request.body.intState,
                        L: request.body.intLocation,
                        O: request.body.intOrganization,
                        OU: request.body.intUnit,
                        CN: request.body.intCommonName
                    };
                    let errString = '';
                    if (!subject.CN)
                        errString += 'Common name is required</br>\n';
                    if (!validTo)
                        errString += 'Valid to is required\n';
                    if (errString) {
                        return response.status(400).json({ message: errString });
                    }
                    const cRow = this._certificates.findOne({ name: request.body.intSigner });
                    const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });
                    if (!cRow || !kRow) {
                        return response.status(500).json({ message: 'Unexpected database corruption - rows missing' });
                    }
                    const c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, cRow.name + '.pem'), { encoding: 'utf8' }));
                    let k;
                    if (c) {
                        if (request.body.intPassword) {
                            k = node_forge_1.pki.decryptRsaPrivateKey(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }), request.body.intPassword);
                        }
                        else {
                            k = node_forge_1.pki.privateKeyFromPem(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }));
                        }
                    }
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = this._getAttributes(subject);
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
                    cert.serialNumber = this._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newint.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newint-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newint.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newint-key.pem')));
                    let retTypes = Array.from(new Set(certResult.types.concat(keyResult.types).concat([CertTypes.intermediate]))).map((type) => CertTypes[type]);
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, types: retTypes.join(';') });
                }
                catch (err) {
                    return response.status(500).json({ message: err.message });
                }
            }));
            this._app.post('/createLeafCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    let validFrom = request.body.leafValidFrom ? new Date(request.body.leafValidFrom) : new Date();
                    let validTo = request.body.leafValidTo ? new Date(request.body.leafValidTo) : null;
                    let subject = {
                        C: request.body.leafCountry,
                        ST: request.body.leafState,
                        L: request.body.leafLocation,
                        O: request.body.leafOrganization,
                        OU: request.body.leafUnit,
                        CN: request.body.leafCommonName
                    };
                    let errString = '';
                    if (!subject.CN)
                        errString += 'Common name is required</br>\n';
                    if (!validTo)
                        errString += 'Valid to is required\n';
                    if (errString) {
                        return response.status(400).json({ message: errString });
                    }
                    const cRow = this._certificates.findOne({ name: request.body.leafSigner });
                    const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });
                    if (!cRow || !kRow) {
                        return response.status(500).json({ message: 'Unexpected database corruption - rows missing' });
                    }
                    const c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, cRow.name + '.pem'), { encoding: 'utf8' }));
                    let k;
                    if (c) {
                        if (request.body.leafPassword) {
                            k = node_forge_1.pki.decryptRsaPrivateKey(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }), request.body.leafPassword);
                        }
                        else {
                            k = node_forge_1.pki.privateKeyFromPem(fs_1.default.readFileSync(path_1.default.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }));
                        }
                    }
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = this._getAttributes(subject);
                    let sal = { domains: [subject.CN] };
                    let extensions = [
                        new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: false }),
                        new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}),
                        new ExtensionKeyUsage_1.ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
                        new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                        new ExtensionExtKeyUsage_1.ExtensionExtKeyUsage({ serverAuth: true }),
                        new ExtensionSubjectAltName_1.ExtensionSubjectAltName(sal),
                    ];
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    // Set the Certificate attributes for the new Root CA
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = this._getRandomSerialNumber();
                    cert.validity.notBefore = validFrom;
                    cert.validity.notAfter = validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign the Certificate
                    cert.sign(k, node_forge_1.md.sha512.create());
                    // Convert to PEM format
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newleaf.pem'), node_forge_1.pki.certificateToPem(cert), { encoding: 'utf8' });
                    fs_1.default.writeFileSync(path_1.default.join(this._workPath, 'newleaf-key.pem'), node_forge_1.pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                    let certResult = yield this._tryAddCertificate((path_1.default.join(this._workPath, 'newleaf.pem')));
                    let keyResult = yield this._tryAddKey((path_1.default.join(this._workPath, 'newleaf-key.pem')));
                    let retTypes = Array.from(new Set(certResult.types.concat(keyResult.types).concat([CertTypes.leaf]))).map((type) => CertTypes[type]);
                    return response.status(200)
                        .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, types: retTypes.join(';') });
                }
                catch (err) {
                    return response.status(500).json({ message: err.message });
                }
            }));
            if (this._certificate) {
                const options = {
                    cert: this._certificate,
                    key: this._key,
                };
                https_1.default.createServer(options, this._app).listen(this._port, '0.0.0.0');
            }
            else {
                http_1.default.createServer(this._app).listen(this._port, '0.0.0.0');
            }
            // this._app.listen(this._port, () => {
            //     logger.info(`Listen on the port ${WebServer.getWebServer().port}...`);
            // });
            logger.info('Starting');
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
                    let caList = this._certificates.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
                    let nonRoot = this._certificates.find({ '$and': [{ 'type': { '$ne': CertTypes.root } }, { signedBy: null }] });
                    // let nonRoot = certificates.chain().find({ 'type': certTypes.root }).find({ 'signedBy': null });
                    for (let i = 0; i < nonRoot.length; i++) {
                        let signer = yield this._findSigner(caList, node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, nonRoot[i].name + '.pem'), { encoding: 'utf8' })));
                        if (signer != -1) {
                            logger.info(`${nonRoot[i].name} is signed by ${caList[signer].name}`);
                            nonRoot[i].signedBy = caList[signer].serialNumber;
                            this._certificates.update(nonRoot[i]);
                        }
                    }
                    let keyRows = this._privateKeys.chain().simplesort('name').data();
                    keyRows.forEach((key) => {
                        if (!(0, node_fs_1.existsSync)(path_1.default.join(this._privatekeysPath, key.name + '.pem'))) {
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
                            catch (err) { }
                        }
                    }));
                    // addresults = await Promise.all(adding);
                    yield Promise.all(adding);
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
                    let pemString = fs_1.default.readFileSync(filename, { encoding: 'utf8' });
                    let msg = node_forge_1.pem.decode(pemString)[0];
                    logger.debug(`Received ${msg.type}`);
                    if (msg.type != 'CERTIFICATE') {
                        throw new CertError(400, 'Unsupported type ' + msg.type);
                    }
                    let result;
                    let c = node_forge_1.pki.certificateFromPem(pemString);
                    let types = [];
                    let signedBy = null;
                    let havePrivateKey = false;
                    // See if we already have this certificate
                    if (this._certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                        throw new CertError(409, `${path_1.default.basename(filename)} serial number ${c.serialNumber} is a duplicate - ignored`);
                    }
                    // See if this is a root, intermiate, or leaf
                    if (c.isIssuer(c)) {
                        types.push(CertTypes.root);
                        signedBy = c.serialNumber;
                    }
                    else {
                        let bc = c.getExtension('basicConstraints');
                        if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                            types.push(CertTypes.intermediate);
                        }
                        else {
                            types.push(CertTypes.leaf);
                        }
                        // See if any existing certificates signed this one
                        let caList = this._certificates.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
                        let signer = yield this._findSigner(caList, c);
                        if (signer != -1) {
                            signedBy = caList[signer].serialNumber;
                        }
                    }
                    if (types[0] != CertTypes.leaf) {
                        // Update certificates that this one signed
                        let signeeList = this._certificates.find({ 'type': { '$in': [CertTypes.leaf, CertTypes.intermediate] } });
                        let list = yield this._findSigned(signeeList, c);
                        if (list.length > 0) {
                            list.forEach((l) => logger.info(`${l} marked signed by new certificate`));
                        }
                        types = types.concat(list);
                    }
                    // Generate a filename for the common name
                    let name = (c.subject.getField('CN').value).replace(/ /g, '_');
                    // Deduplicate if necessary
                    if (name + '.pem' != path_1.default.basename(filename)) {
                        if (fs_1.default.existsSync(path_1.default.join(path_1.default.dirname(filename), name + '.pem'))) {
                            for (let i = 1; true; i++) {
                                if (!fs_1.default.existsSync(path_1.default.join(path_1.default.dirname(filename), name + '_' + i.toString() + '.pem'))) {
                                    name = name + '_' + i.toString();
                                    break;
                                }
                            }
                        }
                        logger.info(`Renamed ${path_1.default.basename(filename)} to ${name}.pem`);
                        fs_1.default.renameSync(filename, path_1.default.join(this._certificatesPath, name + '.pem'));
                        // See if we have private key for this certificate
                        let keys = this._privateKeys.chain().find({ pairSerial: null }).data();
                        for (let i = 0; i < keys.length; i++) {
                            if (this._isSignedBy(c, keys[i].n, keys[i].e)) {
                                logger.info('Found private key for ' + name);
                                havePrivateKey = true;
                                fs_1.default.renameSync(path_1.default.join(this._privatekeysPath, keys[i].name + '.pem'), path_1.default.join(this._privatekeysPath, name + '_key.pem'));
                                keys[i].name = name + '_key';
                                keys[i].pairSerial = c.serialNumber;
                                this._privateKeys.update(keys[i]);
                                break;
                            }
                        }
                    }
                    logger.info(`Certificate ${name} added`);
                    this._certificates.insert({
                        name: name,
                        type: types[0],
                        serialNumber: c.serialNumber,
                        publicKey: c.publicKey,
                        privateKey: null,
                        signedBy: signedBy,
                        issuer: this._getSubject(c.issuer),
                        subject: this._getSubject(c.subject),
                        notBefore: c.validity.notBefore,
                        notAfter: c.validity.notAfter,
                        havePrivateKey: havePrivateKey,
                    });
                    result = { name: name, types: (Array.from(new Set(types))) };
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
        let signer = (r.signedBy == null) ? null : this._certificates.findOne({ serialNumber: r.signedBy }).name;
        let key = this._privateKeys.findOne({ pairSerial: r.serialNumber });
        return {
            certType: CertTypes[r.type],
            name: r.name,
            issuer: r.issuer,
            subject: r.subject,
            validFrom: r.notBefore,
            validTo: r.notAfter,
            serialNumber: r.serialNumber.match(/.{1,2}/g).join(':'),
            signer: signer,
            keyPresent: key != null ? 'yes' : 'no',
            // TODO: Add reference to signer
        };
    }
    _tryDeleteCert(options) {
        var _a;
        let cert = this._certificates.findOne(options.serialNumber ? { serialNumber: options.serialNumber } : { name: options.name });
        if (!cert) {
            throw new CertError(404, `Unable to find certificate with ${options.serialNumber ? 'serial number' : 'name'} ${(_a = options.serialNumber) !== null && _a !== void 0 ? _a : options.name}`);
        }
        let filename = path_1.default.join(this._certificatesPath, cert.name + '.pem');
        if ((0, node_fs_1.existsSync)(filename)) {
            fs_1.default.unlinkSync(filename);
        }
        let certTypes = [];
        certTypes.push(cert.type);
        let key = this._privateKeys.findOne({ pairSerial: cert.serialNumber });
        if (key) {
            key.pairSerial = null;
            let unknownName = this._getUnpairedKeyName();
            fs_1.default.renameSync(path_1.default.join(this._privatekeysPath, key.name + '.pem'), path_1.default.join(this._privatekeysPath, unknownName + '.pem'));
            key.name = unknownName;
            this._privateKeys.update(key);
            certTypes.push(CertTypes.key);
        }
        let signedBy = this._certificates.find({ signedBy: cert.serialNumber });
        for (let i = 0; i < signedBy.length; i++) {
            certTypes.push(signedBy[i].type);
        }
        this._certificates.remove(cert);
        return { name: cert.name, types: (Array.from(new Set(certTypes))) };
    }
    _tryAddKey(filename, password) {
        return __awaiter(this, void 0, void 0, function* () {
            logger.info(`Trying to add ${path_1.default.basename(filename)}`);
            if (!fs_1.default.existsSync(filename)) {
                let err = new CertError(404, `${path_1.default.basename(filename)} does not exist`);
                throw err;
            }
            try {
                let k;
                let kpem = fs_1.default.readFileSync(filename, { encoding: 'utf8' });
                let msg = node_forge_1.pem.decode(kpem)[0];
                let encrypted = false;
                if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                    if (!password) {
                        throw new CertError(400, 'Password is required');
                    }
                    k = node_forge_1.pki.decryptRsaPrivateKey(fs_1.default.readFileSync(filename, { encoding: 'utf8' }), password);
                    encrypted = true;
                }
                else {
                    k = node_forge_1.pki.privateKeyFromPem(fs_1.default.readFileSync(filename, { encoding: 'utf8' }));
                }
                let krow = { e: k.e, n: k.n, pairSerial: null, name: null, type: CertTypes.key, encrypted: encrypted };
                let keys = this._privateKeys.find();
                let publicKey = node_forge_1.pki.setRsaPublicKey(k.e, k.n);
                // See if we already have this key
                for (let i = 0; i < keys.length; i++) {
                    if (this._isIdenticalKey(node_forge_1.pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                        throw new CertError(409, `Key already present: ${keys[i].name}`);
                    }
                }
                // See if this is the key pair for a certificate
                let certs = this._certificates.find();
                let newfile = 'unknown_key_';
                let types = [CertTypes.key];
                for (let i = 0; i < certs.length; i++) {
                    if (this._isSignedBy(yield this._cache.getCertificate(certs[i].name), k.n, k.e)) {
                        krow.pairSerial = certs[i].serialNumber;
                        types.push(certs[i].type);
                        newfile = certs[i].name + '_key';
                        break;
                    }
                }
                // Generate a file name for a key without a certificate
                if (krow.pairSerial == null) {
                    newfile = this._getUnpairedKeyName();
                }
                fs_1.default.renameSync(filename, path_1.default.join(this._privatekeysPath, newfile + '.pem'));
                logger.info(`Renamed ${path_1.default.basename(filename)} to ${newfile}.pem`);
                krow.name = newfile;
                this._privateKeys.insert(krow);
                return { name: newfile, types: types };
            }
            catch (err) {
                logger.error(err.message);
                if (!err.status) {
                    err.status = 500;
                }
                throw err;
            }
        });
    }
    _getKeyBrief(r) {
        return {
            name: r.name,
            certPair: (r.pairSerial == null) ? 'Not present' : r.name.substring(0, r.name.length - 4),
            encrypted: r.encrypted,
        };
    }
    _tryDeleteKey(options) {
        let key = this._privateKeys.findOne({ name: options.name });
        if (!key) {
            throw new CertError(404, `Unable to find key with name ${options.name}`);
        }
        let filename = path_1.default.join(this._privatekeysPath, key.name + '.pem');
        if ((0, node_fs_1.existsSync)(filename)) {
            fs_1.default.unlinkSync(filename);
        }
        let certTypes = [CertTypes.key];
        if (key.pairSerial) {
            let cert = this._certificates.findOne({ serialNumber: key.pairSerial });
            if (!cert) {
                logger.warn(`Could not find certificate with serial number ${key.pairSerial}`);
            }
            else {
                cert.havePrivateKey = false;
                this._certificates.update(cert);
                certTypes.push(cert.type);
            }
        }
        this._privateKeys.remove(key);
        return { name: key.name, types: certTypes };
    }
    _getSubject(s) {
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
    _getUnpairedKeyName() {
        let newname = 'unknown_key_';
        for (let i = 0; true; i++) {
            if (!fs_1.default.existsSync(path_1.default.join(this._privatekeysPath, newname + i.toString() + '.pem'))) {
                return newname + i.toString();
            }
        }
    }
    _findSigner(caList, certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
                if (caList) {
                    for (let i = 0; i < caList.length; i++) {
                        try {
                            let c = yield this._cache.getCertificate(caList[i].name);
                            if (c.verify(certificate)) {
                                resolve(i);
                            }
                        }
                        catch (_err) {
                            logger.debug('Not ' + caList[i].name);
                            // verify should return false but appearently throws an exception - do nothing
                        }
                    }
                }
                resolve(-1);
            }));
        });
    }
    _findSigned(signeeList, certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let retVal = [];
                try {
                    signeeList.forEach((s) => __awaiter(this, void 0, void 0, function* () {
                        let check = yield this._cache.getCertificate(s.name);
                        try {
                            if (certificate.verify(check)) {
                                this._certificates.chain().find({ 'serialNumber': check.serialNumber }).update((u) => {
                                    u.signedBy = certificate.serialNumber;
                                });
                                logger.debug(`Marked ${s.name} as signed by ${certificate.subject.getField('CN')}`);
                                retVal.push(s.type);
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
    _isSignedBy(cert, keyn, keye) {
        let publicKey = node_forge_1.pki.setRsaPublicKey(keyn, keye);
        let certPublicKey = cert.publicKey;
        return this._isIdenticalKey(publicKey, certPublicKey);
        // if (publicKey.n.data.length != certPublicKey.n.data.length) return false;
        // for (let i = 0; i < publicKey.n.data.length; i++) {
        //     if (publicKey.n.data[i] != certPublicKey.n.data[i]) {
        //         return false;
        //     }
        // }
        // return true;
    }
    _isIdenticalKey(leftKey, rightKey) {
        if (leftKey.n.data.length != rightKey.n.data.length) {
            return false;
        }
        for (let i = 0; i < leftKey.n.data.length; i++) {
            if (leftKey.n.data[i] != rightKey.n.data[i])
                return false;
        }
        return true;
    }
    _getAttributes(subject) {
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
    _getRandomSerialNumber() {
        return this._makeNumberPositive(node_forge_1.util.bytesToHex(node_forge_1.random.getBytesSync(20)));
    }
}
exports.WebServer = WebServer;
WebServer.instance = null;
//# sourceMappingURL=webserver.js.map