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
// import { ExtensionParent } from './extensions/ExtensionParent';
// import { ExtensionBasicConstraints } from './extensions/ExtensionBasicConstraints';
// import { ExtensionKeyUsage } from './extensions/ExtensionKeyUsage';
// import { ExtensionAuthorityKeyIdentifier } from './extensions/ExtensionAuthorityKeyIdentifier';
// import { ExtensionSubjectKeyIdentifier } from './extensions/ExtensionSubjectKeyIdentifier';
// import { ExtensionExtKeyUsage } from './extensions/ExtensionExtKeyUsage';
// import { ExtensionSubjectAltName, ExtensionSubjectAltNameOptions } from './extensions/ExtensionSubjectAltName';
const OperationResult_1 = require("./webservertypes/OperationResult");
const CertTypes_1 = require("./webservertypes/CertTypes");
const userAgentOS_1 = require("./webservertypes/userAgentOS");
const CertError_1 = require("./webservertypes/CertError");
const CertMultiError_1 = require("./webservertypes/CertMultiError");
// import { CertificateInput } from './webservertypes/CertificateInput';
const keyStores_1 = require("./database/keyStores");
const keyUtil_1 = require("./database/keyUtil");
const certificateStores_1 = require("./database/certificateStores");
const certificateUtil_1 = require("./database/certificateUtil");
const OperationResultItem_1 = require("./webservertypes/OperationResultItem");
const dbStores_1 = require("./database/dbStores");
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
                certificateStores_1.CertificateStores.Init(certificates, path_1.default.join(this._dataPath, 'certificates'));
                keyStores_1.KeyStores.Init(privateKeys, path_1.default.join(this._dataPath, 'privatekeys'));
                dbStores_1.DbStores.Init(dbVersion);
                yield this._dbInit();
            }
            catch (err) {
                logger.fatal('Failed to initialize the database: ' + err.message);
                process.exit(4);
            }
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
            this._app.use((request, response, next) => {
                var _a;
                const redirects = {
                    '/api/uploadCert': '/api/uploadPem',
                    '/api/helpers': '/api/helper',
                    '/api/script': '/api/helper',
                    '/createCACert': '/api/createCACert',
                    '/createIntermediateCert': '/api/createIntermediateCert',
                    '/createLeafCert': '/api/createLeafCert',
                    '/deleteCert': '/api/deleteCert',
                    '/certList': '/api/certList',
                    '/certDetails': '/api/certDetails',
                    '/deleteKey': '/api/deleteKey',
                    '/keyList': '/certList',
                    '/keyDetails': '/api/keyDetails',
                    '//api/getCertPem': '/api/getCertificatePem',
                    '/api/uploadKey': '/api/uploadPem',
                };
                try {
                    if (request.path in redirects) {
                        logger.debug(`Redirecting ${request.path} to ${redirects[request.path]}`);
                        request.url = redirects[request.path];
                    }
                    logger.debug(`${request.method} ${request.url}`);
                    next();
                }
                catch (err) {
                    response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json({ error: err.message });
                }
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
            // this._app.get('/api/helpers', (request, _response, next) => {
            //     request.url = '/api/helper';
            //     next();
            // });
            // this._app.get('/api/script', (request, _response, next) => {
            //     request.url = '/api/helper';
            //     next();
            // });
            this._app.get('/api/helper', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
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
                    logger.debug('Sending file');
                    readable.pipe(response);
                }
                catch (err) {
                    logger.error(err);
                }
            }));
            // this._app.post('/createCACert', async (request, _response, next) => {
            //     request.url = '/api/createCACert'
            //     next();
            // });
            // this._app.post('/createIntermediateCert', async (request, _response, next) => {
            //     request.url = '/api/createIntermediateCert';
            //     next();
            // });
            // this._app.post('/createLeafCert', async (request, _response, next) => {
            //     request.url = '/api/createLeafCert';
            //     next();
            // });
            this._app.post('/updateCertTag', (request, _response, next) => __awaiter(this, void 0, void 0, function* () {
                request.url = '/api/updateCertTag';
                request.query['id'] = request.body.toTag;
                next();
            }));
            // this._app.delete('/deleteCert', ((request: any, _response: any, next: NextFunction) => {
            //     request.url = '/api/deleteCert';
            //     next();
            // }));
            // this._app.get('/certList', (request: any, _response: any, next: NextFunction) => {
            //     request.url = '/api/certList';
            //     next();
            // });
            // this._app.get('/certDetails', async (request: any, _response: any, next: NextFunction) => {
            //     request.url = '/api/certDetails';
            //     next();
            // });
            // this._app.delete('/deleteKey', ((request, _response, next: NextFunction) => {
            //     request.url = '/api/deleteKey';
            //     next();
            // }))
            // this._app.get('/keyList', (request, _response, next: NextFunction) => {
            //     request.url = '/certList';
            //     next();
            // });
            // this._app.get('/keyDetails', async (request, _response, next) => {
            //     request.url = '/api/keyDetails';
            //     next();
            // });
            this._app.post(/\/api\/create.*Cert/i, (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    logger.debug(request.body);
                    // let certInput: CertificateInput = WebServer._validateCertificateInput(CertTypes.root, request.body);
                    // const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                    // const attributes = WebServer._setAttributes(certInput.subject);
                    // const extensions: ExtensionParent[] = [
                    //     new ExtensionBasicConstraints({ cA: true, critical: true }),
                    //     new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    //     // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, keyIdentifier: true }),
                    //     new ExtensionSubjectKeyIdentifier({ }),
                    // ]
                    // // Create an empty Certificate
                    // let cert = pki.createCertificate();
                    // // Set the Certificate attributes for the new Root CA
                    // cert.publicKey = publicKey;
                    // // cert.privateKey = privateKey;
                    // cert.serialNumber = WebServer._getRandomSerialNumber();
                    // cert.validity.notBefore = certInput.validFrom;
                    // cert.validity.notAfter = certInput.validTo;
                    // cert.setSubject(attributes);
                    // cert.setIssuer(attributes);
                    // cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // // Self-sign the Certificate
                    // cert.sign(privateKey, md.sha512.create());
                    // Convert to PEM format
                    let type = request.url.includes('createCACert')
                        ? CertTypes_1.CertTypes.root
                        : request.url.includes('createIntermediateCert')
                            ? CertTypes_1.CertTypes.intermediate
                            : CertTypes_1.CertTypes.leaf;
                    let { certificatePem, keyPem, result } = yield certificateUtil_1.CertificateUtil.generateCertificatePair(type, request.body);
                    if (result.hasErrors) {
                        return response.status(result.statusCode).json(result.getResponse());
                    }
                    let certResult = yield this._tryAddCertificate({ pemString: certificatePem });
                    let keyResult = yield this._tryAddKey({ pemString: keyPem });
                    certResult.merge(keyResult);
                    certResult.name = `${certResult.name}/${keyResult.name}`;
                    this._broadcast(certResult);
                    let certId = certResult.added[0].id;
                    let keyId = keyResult.added[0].id;
                    return response.status(200)
                        .json({
                        success: true,
                        title: 'Certificate/Key Added',
                        messages: [`Certificate/Key ${certResult.name}/${keyResult.name} added`],
                        newIds: { certificateId: certId, keyId: keyId }
                    });
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            // this._app.post('/api/createIntermediateCert', async (request, response) => {
            //     try {
            //         logger.debug(request.body);
            //         let certInput: CertificateInput = WebServer._validateCertificateInput(CertTypes.intermediate, request.body);
            //         const cRow = CertificateStores.findOne({ $loki: parseInt(certInput.signer) });
            //         const kRow = KeyStores.findOne({ $loki: cRow.keyId })
            //         if (!cRow || !kRow) {
            //             return response.status(404).json({ error: 'Signing certificate or key are either missing or invalid' });
            //         }
            //         const c: pki.Certificate = await cRow.getpkiCert();
            //         const k: pki.PrivateKey = await kRow.getpkiKey(certInput.password);
            //         const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
            //         const attributes = WebServer._setAttributes(certInput.subject);
            //         const extensions: ExtensionParent[] = [
            //             new ExtensionBasicConstraints({ cA: true, critical: true }),
            //             new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
            //             new ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
            //             new ExtensionSubjectKeyIdentifier({ }),
            //         ];
            //         if (certInput.san.domains.length > 0 || certInput.san.IPs.length > 0) {
            //             let sal: ExtensionSubjectAltNameOptions = {};
            //             sal.domains = certInput.san.domains;
            //             sal.IPs = certInput.san.IPs;
            //             extensions.push(new ExtensionSubjectAltName(sal));
            //         }
            //         // Create an empty Certificate
            //         let cert = pki.createCertificate();
            //         // Set the Certificate attributes for the new Root CA
            //         cert.publicKey = publicKey;
            //         cert.serialNumber = WebServer._getRandomSerialNumber();
            //         cert.validity.notBefore = certInput.validFrom;
            //         cert.validity.notAfter = certInput.validTo;
            //         cert.setSubject(attributes);
            //         cert.setIssuer(c.subject.attributes);
            //         cert.setExtensions(extensions.map((extension) => extension.getObject()));
            //         // Sign with parent certificate's private key
            //         cert.sign(k, md.sha512.create());
            //         // Convert to PEM format
            //         let certResult = await this._tryAddCertificate({ pemString: pki.certificateToPem(cert) });
            //         let keyResult = await this._tryAddKey({ pemString: pki.privateKeyToPem(privateKey) });
            //         certResult.merge(keyResult);
            //         certResult.name = `${certResult.name}/${keyResult.name}`;
            //         this._broadcast(certResult);
            //         let certId = certResult.added[0].id;
            //         let keyId = keyResult.added[0].id;
            //         return response.status(200)
            //             .json({ message: `Certificate/Key ${certResult.name} added`, ids: { certificateId: certId, keyId: keyId } });
            //     }
            //     catch (err) {
            //         logger.error(`Failed to create intermediate certificate: ${err.message}`);
            //         return response.status(500).json({ error: err.message });
            //     }
            // });
            // this._app.post('/api/createLeafCert', async (request, response) => {
            //     try {
            //         logger.debug(request.body);
            //         let certInput: CertificateInput = WebServer._validateCertificateInput(CertTypes.leaf, request.body);
            //         const cRow = CertificateStores.findOne({ $loki: parseInt(certInput.signer) });
            //         const kRow = KeyStores.findOne({ $loki: cRow.keyId })
            //         if (!cRow || !kRow) {
            //             return response.status(500).json({ error: 'Signing certificate or key are either missing or invalid'});
            //         }
            //         const c: pki.Certificate = await cRow.getpkiCert();
            //         const k: pki.PrivateKey = await kRow.getpkiKey(certInput.password);
            //         const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
            //         const attributes = WebServer._setAttributes(certInput.subject);
            //         let sal:ExtensionSubjectAltNameOptions = { };
            //         sal.domains = certInput.san.domains;
            //         sal.IPs = certInput.san.IPs;
            //         let extensions: ExtensionParent[] = [
            //             new ExtensionBasicConstraints({ cA: false }),
            //             new ExtensionSubjectKeyIdentifier({ }),
            //             new ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
            //             new ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
            //             new ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true,  }),
            //             new ExtensionSubjectAltName(sal),
            //         ];
            //         // Create an empty Certificate
            //         let cert = pki.createCertificate();
            //         // Set the Certificate attributes for the new Root CA
            //         cert.publicKey = publicKey;
            //         // cert.privateKey = privateKey;
            //         cert.serialNumber = WebServer._getRandomSerialNumber();
            //         cert.validity.notBefore = certInput.validFrom;
            //         cert.validity.notAfter = certInput.validTo;
            //         cert.setSubject(attributes);
            //         cert.setIssuer(c.subject.attributes);
            //         cert.setExtensions(extensions.map((extension) => extension.getObject()));
            //         // Sign the certificate with the parent's key
            //         cert.sign(k, md.sha512.create());
            //         // Convert to PEM format
            //         let certResult = await this._tryAddCertificate({ pemString: pki.certificateToPem(cert) });
            //         let keyResult = await this._tryAddKey({ pemString: pki.privateKeyToPem(privateKey) });
            //         certResult.merge(keyResult);
            //         certResult.name = `${certResult.name}/${keyResult.name}`;
            //         this._broadcast(certResult);
            //         let certId = certResult.added[0].id;
            //         let keyId = keyResult.added[0].id;
            //         return response.status(200)
            //             .json({ message: `Certificate/Key ${certResult.name} added`, ids: { certificateId: certId, keyId: keyId } });
            //     }
            //     catch (err) {
            //         logger.error(`Error creating leaf certificate: ${err.message}`);
            //         return response.status(500).json({ error: err.message })
            //     }
            // });
            this._app.get('/api/certName', (request, response) => __awaiter(this, void 0, void 0, function* () {
                var _a;
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    return response.status(200).json({ name: c.subject.CN, id: c.$loki, tags: (_a = c.tags) !== null && _a !== void 0 ? _a : [] });
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/certDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let retVal = c.certificateBrief();
                    response.status(200).json(retVal);
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/keyList', (request, _response, next) => {
                request.url = '/api/certList';
                request.query = { type: 'key' };
                next();
            });
            this._app.get('/api/keyDetails', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let k = this._resolveKeyQuery(request.query);
                    let retVal = k.keyBrief;
                    response.status(200).json(retVal);
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/certList', (request, response) => {
                try {
                    let type = CertTypes_1.CertTypes[request.query.type];
                    if (type == undefined) {
                        throw new CertError_1.CertError(404, `Directory ${request.query.type} not found`);
                    }
                    else {
                        let retVal = [];
                        if (type != CertTypes_1.CertTypes.key) {
                            retVal = certificateStores_1.CertificateStores.find({ type: type }).sort((l, r) => l.name.localeCompare(r.name)).map((entry) => {
                                var _a;
                                return {
                                    name: entry.subject.CN,
                                    type: CertTypes_1.CertTypes[type].toString(),
                                    id: entry.$loki,
                                    tags: (_a = entry.tags) !== null && _a !== void 0 ? _a : [],
                                    keyId: entry.keyId
                                };
                            });
                        }
                        else {
                            retVal = keyStores_1.KeyStores.find().sort((l, r) => l.name.localeCompare(r.name)).map((entry) => {
                                return {
                                    name: entry.name,
                                    type: CertTypes_1.CertTypes[type].toString(),
                                    id: entry.$loki
                                };
                            });
                        }
                        return response.status(200).json({ files: retVal });
                    }
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            });
            // this._app.get('/api/getCertPem', async (request, _response, next) => {
            //     request.url = '/api/getCertificatePem';
            //     next();
            // });
            this._app.get('/api/getCertificatePem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    response.download(c.absoluteFilename, c.name + '.pem', (err) => {
                        if (err) {
                            throw new CertError_1.CertError(500, `Failed to find file for ${request.query}: ${err.message}`);
                        }
                    });
                }
                catch (err) {
                    logger.error('Certificate download failed: ', err.message);
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.delete('/api/deleteCert', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let result = yield this._tryDeleteCert(c);
                    this._broadcast(result);
                    return response.status(200).json(result.getResponse());
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.post('/api/updateCertTag', (request, response) => __awaiter(this, void 0, void 0, function* () {
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
                        c.updateTags(cleanedTags);
                    });
                    result.pushMessage('Certificate tags updated', OperationResult_1.ResultType.Success);
                    this._broadcast(result);
                    return response.status(200).json(result.getResponse());
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/keyname', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let k = this._resolveKeyQuery(request.query);
                    response.status(200).json({ name: k.name, id: k.$loki, tags: [] });
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            // this._app.post('/api/uploadKey', async (request, _response, next) => {
            //     request.url = '/api/uploadPem';
            //     next();
            // });
            this._app.delete('/api/deleteKey', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let k = this._resolveKeyQuery(request.query);
                    let result = yield this._tryDeleteKey(k);
                    this._broadcast(result);
                    return response.status(200).json(result.getResponse());
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/getKeyPem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let k = this._resolveKeyQuery(request.query);
                    response.download(k.absoluteFilename, k.name + '.pem', (err) => {
                        if (err) {
                            throw new CertError_1.CertError(404, `Failed to file for ${request.query.id}: ${err.message}`);
                        }
                    });
                }
                catch (err) {
                    logger.error('Key download failed: ', err.message);
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            /**
             * Upload pem format files. These can be key, a certificate, or a file that
             * contains keys or certificates.
             */
            this._app.post('/uploadPem', ((request, response) => __awaiter(this, void 0, void 0, function* () {
                // FUTURE: Allow der and pfx files to be submitted
                if (!request.files || Object.keys(request.files).length == 0) {
                    return response.status(400).json({ error: 'No file selected' });
                }
                try {
                    let files = request.files.certFile;
                    if (!Array.isArray(files)) {
                        files = [files];
                    }
                    let result = new OperationResult_1.OperationResult('multiple');
                    for (let f of files) {
                        result.merge(yield this._processMultiFile(f.data.toString()));
                    }
                    if (result.added.length + result.updated.length + result.deleted.length > 0) {
                        this._broadcast(result);
                    }
                    return response.status(200).json(result.getResponse());
                }
                catch (err) {
                    logger.error(`Upload files failed: ${err.message}`);
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            })));
            this._app.post('/api/uploadPem', (request, response) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (request.headers['content-type'] != 'text/plain') {
                        return response.status(400).json(new OperationResult_1.OperationResult('').pushMessage('Content type must be text/plain', OperationResult_1.ResultType.Failed).getResponse());
                    }
                    if (!request.body.includes('\n')) {
                        return response.status(400).json(new OperationResult_1.OperationResult('').pushMessage('Key must be in standard 64 byte line length format - try --data-binary with curl', OperationResult_1.ResultType.Failed).getResponse());
                    }
                    let result = yield this._processMultiFile(request.body);
                    this._broadcast(result);
                    return response.status(200).json(result.getResponse());
                }
                catch (err) {
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.get('/api/ChainDownload', (request, response) => __awaiter(this, void 0, void 0, function* () {
                // BUG - Breaks if there chain is not complete
                try {
                    let c = this._resolveCertificateQuery(request.query);
                    let fileData = yield c.getCertificateChain();
                    response.type('application/text');
                    response.setHeader('Content-Disposition', `attachment; filename="${c.name}_chain.pem"`);
                    response.send(fileData);
                }
                catch (err) {
                    logger.error('Chain download failed: ' + err.message);
                    let e = CertMultiError_1.CertMultiError.getCertError(err);
                    return response.status(e.status).json(e.getResponse());
                }
            }));
            this._app.use((request, response, _next) => {
                var _a;
                try {
                    logger.warn(`No paths match ${request.path}`);
                    response.status(404).json({
                        success: false,
                        title: 'Error',
                        messages: [
                            {
                                message: `No paths match ${request.path}`,
                                type: OperationResult_1.ResultType.Failed
                            }
                        ]
                    });
                }
                catch (err) {
                    response.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).json({
                        success: false,
                        title: 'Error',
                        messages: [
                            {
                                message: err.message,
                                type: OperationResult_1.ResultType.Failed
                            }
                        ]
                    });
                    // response.status(err.status ?? 500).json({ error: err.message });
                }
            });
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
                    let version = dbStores_1.DbStores.find();
                    if (version.length > 1) {
                        logger.fatal('Version table is corrupt. Should only contain one row');
                        process.exit(4);
                    }
                    else if (version.length == 0) {
                        dbStores_1.DbStores.insert({ version: this._currentVersion });
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
                    let certRows = certificateStores_1.CertificateStores.find().sort((l, r) => l.name.localeCompare(r.name));
                    certRows.forEach((row) => {
                        if (!fs_1.default.existsSync(row.absoluteFilename)) {
                            logger.warn(`Certificate ${row.name} not found - removed`);
                            certificateStores_1.CertificateStores.bulkUpdate({ $loki: row.signedById }, (r) => {
                                r.signedById = null;
                                logger.warn(`Removed signedBy from ${r.name}`);
                            });
                            keyStores_1.KeyStores.find({ pairId: row.$loki }).forEach((row) => {
                                row.clearCertificateKeyPair();
                                logger.warn(`Removed relationship to private key from ${row.name}`);
                            });
                            row.remove();
                        }
                    });
                    files = fs_1.default.readdirSync(certificateStores_1.CertificateStores.CertificatePath);
                    let adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        let cert = certificateStores_1.CertificateStores.findOne({ $loki: certificateUtil_1.CertificateUtil.getIdFromFileName(file) });
                        if (!cert) {
                            try {
                                adding.push(this._tryAddCertificate({ filename: cert.absoluteFilename }));
                            }
                            catch (err) { }
                        }
                    }));
                    yield Promise.all(adding);
                    let nonRoot = certificateStores_1.CertificateStores.find({ '$and': [{ 'type': { '$ne': CertTypes_1.CertTypes.root } }, { signedById: null }] });
                    for (let r of nonRoot) {
                        let signer = yield r.findSigner();
                        if (signer != null) {
                            logger.info(`${r.name} is signed by ${signer.name}`);
                            r.updateSignedById(signer.$loki);
                        }
                        else {
                            logger.warn(`${r.name} is not signed by any certificate`);
                        }
                    }
                    let keyRows = keyStores_1.KeyStores.find().sort((l, r) => l.name.localeCompare(r.name));
                    for (let k of keyRows) {
                        if (!(0, node_fs_1.existsSync)(k.absoluteFilename)) {
                            logger.warn(`Key ${k.name} not found - removed`);
                            k.remove();
                        }
                    }
                    ;
                    files = fs_1.default.readdirSync(this._privatekeysPath);
                    adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        let key = keyStores_1.KeyStores.findOne({ $loki: keyUtil_1.KeyUtil.getIdFromFileName(file) });
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
     * Processes a multi-file PEM string and adds the certificates or keys to the server.
     * @param pemString The multi-file PEM string to process.
     * @returns A promise that resolves to an OperationResult indicating the result of the operation.
     */
    _processMultiFile(pemString) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let result = new OperationResult_1.OperationResult('multiple');
                try {
                    // TODO: Put this in CertificateUtil
                    let msg = node_forge_1.pem.decode(pemString);
                    if (msg.length == 0) {
                        throw new CertError_1.CertError(400, 'Could not decode the file as a pem certificate');
                    }
                    for (let m of msg) {
                        logger.debug(`Processing ${m.type}`);
                        let oneRes;
                        try {
                            if (m.type.includes('CERTIFICATE')) {
                                // TODO: Put this in CertificateUtil
                                oneRes = yield this._tryAddCertificate({ pemString: node_forge_1.pem.encode(m, { maxline: 64 }) });
                            }
                            else if (m.type.includes('KEY')) {
                                // TODO: Put this in CertificateUtil
                                oneRes = yield this._tryAddKey({ pemString: node_forge_1.pem.encode(m, { maxline: 64 }) });
                            }
                            else {
                                throw new CertError_1.CertError(409, `Unsupported type ${m.type}`);
                            }
                            result.merge(oneRes);
                        }
                        catch (err) {
                            // logger.error(err.message);
                            result.pushMessage(err.message, OperationResult_1.ResultType.Failed);
                        }
                    }
                    resolve(result);
                }
                catch (err) {
                    result.pushMessage(err.message, OperationResult_1.ResultType.Failed);
                    resolve(result);
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
                try {
                    if (!input.pemString) {
                        logger.info(`Trying to add ${path_1.default.basename(input.filename)}`);
                        if (!(yield (0, exists_1.exists)(input.filename))) {
                            reject(new CertError_1.CertError(404, `${path_1.default.basename(input.filename)} does not exist`));
                        }
                        input.pemString = yield (0, promises_1.readFile)(input.filename, { encoding: 'utf8' });
                    }
                    // TODO: Put this in CertificateUtil
                    let msg = node_forge_1.pem.decode(input.pemString)[0];
                    logger.debug(`Received ${msg.type}`);
                    if (msg.type != 'CERTIFICATE') {
                        throw new CertError_1.CertError(400, 'Unsupported type ' + msg.type);
                    }
                    let result = new OperationResult_1.OperationResult('');
                    let cRow = yield certificateUtil_1.CertificateUtil.createFromPem(input.pemString);
                    logger.debug(`Adding certificate ${cRow.name}`);
                    result.name = cRow.name;
                    result.merge(yield cRow.insert());
                    result.pushMessage(`Certificate ${cRow.name} added`, OperationResult_1.ResultType.Success);
                    logger.info(`Certificate ${cRow.name} added`);
                    cRow.writeFile();
                    logger.info(`Written file ${cRow.name}`);
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
     * Tries to delete a certificate and breaks all the links it has with other certificates and keys if any.
     *
     * @param c The row of the certificate to delete
     * @returns A synopsis of the database updates made as a result of this deletion
     */
    _tryDeleteCert(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (!(yield c.deleteFile())) {
                        logger.error(`Could not find file ${c.absoluteFilename}`);
                    }
                    else {
                        logger.debug(`Deleted file ${c.absoluteFilename}`);
                    }
                    resolve(yield c.remove());
                    logger.debug(`Removed row ${c.name}`);
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
     * @returns OperationResult promise containing updated entries
     */
    _tryAddKey(input) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (!input.pemString) {
                        logger.info(`Trying to add ${path_1.default.basename(input.filename)}`);
                        if (!(yield (0, exists_1.exists)(input.filename))) {
                            throw new CertError_1.CertError(404, `${path_1.default.basename(input.filename)} does not exist`);
                            return;
                        }
                        input.pemString = yield (0, promises_1.readFile)(input.filename, { encoding: 'utf8' });
                    }
                    let result = new OperationResult_1.OperationResult('unknown_key');
                    let kRow = yield keyUtil_1.KeyUtil.CreateFromPem(input.pemString, input.password);
                    // See if we already have this key
                    let match;
                    if ((match = keyStores_1.KeyStores.isIdentical(kRow))) {
                        throw new CertError_1.CertError(409, `Key already present: ${match.name}`);
                    }
                    // Generate a file name for a key without a certificate
                    if (kRow.pairId == null) {
                        result.name = 'unknown_key';
                    }
                    else {
                        result.name = kRow.name;
                    }
                    let temp = kRow.insert();
                    result.merge(temp);
                    result.pushMessage(`Key ${kRow.name} added`, OperationResult_1.ResultType.Success);
                    if (temp.pushUpdated.length > 0) {
                        result.name = temp.name;
                    }
                    logger.info('Inserted key ' + kRow.name);
                    yield kRow.writeFile();
                    logger.info(`Written file ${kRow.name}`);
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
     * Deletes a key's pem file and removes it from the database. If this key has a certificate pair that the certificate will be
     * updated to show that it no longer has its key pair in the system.
     *
     * @param k Key to delete
     * @returns Summary of modifications to the database
     */
    _tryDeleteKey(k) {
        return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            try {
                if (!(yield k.deleteFile())) {
                    logger.error(`Could not find file ${k.absoluteFilename}`);
                }
                else {
                    logger.debug(`Deleted file ${k.absoluteFilename}`);
                }
                resolve(k.remove());
                logger.debug(`Deleted key ${k.name}`);
            }
            catch (err) {
                reject(err);
            }
        }));
    }
    /**
     * Broadcasts the updates to the certificates and keys to all of the web clients
     *
     * @param data the collection of operation results
     */
    _broadcast(data) {
        let msg = JSON.stringify(data.normalize());
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
        if (selector.$loki && isNaN(selector.$loki))
            throw new CertError_1.CertError(400, 'Specified id is not numeric');
        c = certificateStores_1.CertificateStores.find(selector);
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
        let c = certificateStores_1.CertificateStores.find(selector);
        if (c.length == 0) {
            throw new CertError_1.CertError(404, `No certificate for ${query.id ? 'id' : 'name'} ${Object.values(selector)[0]} found`);
        }
        else if (c.length > 1) {
            throw new CertError_1.CertError(400, `Multiple certificates match the name ${Object.values(selector)[0]} - use id instead`);
        }
        let result = new OperationResult_1.OperationResult(c[0].subject.CN);
        result.pushUpdated(new OperationResultItem_1.OperationResultItem(c[0].type, c[0].$loki));
        updater(c[0]);
        c[0].update();
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
        k = keyStores_1.KeyStores.find(selector);
        if (k.length == 0) {
            throw new CertError_1.CertError(404, `No key for ${JSON.stringify(query)} found`);
        }
        else if (k.length > 1) {
            throw new CertMultiError_1.CertMultiError(400, `Multiple keys match the CN ${JSON.stringify(query)} - use id instead`, k.map((l) => l.$loki));
        }
        return k[0];
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
            // this._certificates.find({ $and: [{ signedById: null }, { type: 1 }] }).forEach(r => logger.warn(`Bad signed (${r.$loki}): ${r.subject.CN} - fixing`));
            // this._certificates.chain().find({ $and: [ { signedById: null }, { type: 1 } ] }).update((r) => r.signedById = r.$loki);
            // Check that the database is an older version that needs to be modified
            logger.info('Database is a supported version for this release');
        });
    }
    // private static _validateCertificateInput(type: CertTypes, bodyIn: any): CertificateInput {
    //     // FUTURE Needs a mechanism to force parts of the RDA sequence to be omitted
    //     try {
    //         if (typeof bodyIn !== 'object') {
    //             throw new CertError(400, 'Bad POST data format - use Content-type: application/json');
    //         }
    //         let body: GenerateCertRequest = bodyIn;
    //         let result: CertificateInput = {
    //             validFrom: body.validFrom ? new Date(body.validFrom) : new Date(),
    //             validTo: new Date(body.validTo),
    //             signer: body.signer?? null,
    //             password: body.password?? null,
    //             subject: {
    //                 C: body.country? body.country : null,
    //                 ST: body.state? body.state : null,
    //                 L: body.location? body.location : null,
    //                 O: body.organization? body.organization : null,
    //                 OU: body.unit? body.unit : null,
    //                 CN: body.commonName? body.commonName : null
    //             },
    //             san: {
    //                 domains: [],
    //                 IPs: [],
    //             }
    //         };
    //         let errString: string[] = [];
    //         if (!result.subject.CN) errString.push('Common name is required');
    //         if (!result.validTo) errString.push('Valid to is required');
    //         if (type != CertTypes.root && !body.signer) errString.push('Signing certificate is required')
    //         if (isNaN(result.validTo.valueOf())) errString.push('Valid to is invalid');
    //         if (body.validFrom && isNaN(result.validFrom.valueOf())) errString.push('Valid from is invalid');
    //         if (result.subject.C != null && result.subject.C.length != 2) errString.push('Country code must be omitted or have two characters');
    //         let rc: { valid: boolean, message?: string } = WebServer._isValidRNASequence([result.subject.C, result.subject.ST, result.subject.L, result.subject.O, result.subject.OU, result.subject.CN]);
    //         if (!rc.valid) errString.push(rc.message);
    //         if (errString.length > 0) {
    //             throw new CertError(500, errString.join(';'));
    //         }
    //         if (type == CertTypes.leaf) {
    //             result.san.domains.push(body.commonName);
    //         }
    //         if (type != CertTypes.root && body.SANArray) {
    //             let SANArray = Array.isArray(body.SANArray) ? body.SANArray : [body.SANArray];
    //             let domains = SANArray.filter((entry: string) => entry.startsWith('DNS:')).map((entry: string) => entry.split(' ')[1]);
    //             let ips = SANArray.filter((entry: string) => entry.startsWith('IP:')).map((entry: string) => entry.split(' ')[1]);
    //             if (domains.length > 0) result.san.domains = result.san.domains.concat(domains);
    //             if (ips.length > 0) result.san.IPs = ips;
    //         }
    //         return result;
    //     }
    //     catch (err) {
    //         throw new CertError(500, err.message);
    //     }
    // }
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
}
exports.WebServer = WebServer;
WebServer.instance = null;
WebServer._lowestDBVersion = 0;
//# sourceMappingURL=webserver.js.map