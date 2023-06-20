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
const fs_1 = __importDefault(require("fs"));
const node_forge_1 = require("node-forge");
const lokijs_1 = __importStar(require("lokijs"));
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const serve_favicon_1 = __importDefault(require("serve-favicon"));
const certificateCache_1 = require("./certificateCache");
const eventWaiter_1 = require("./eventWaiter");
var CertTypes;
(function (CertTypes) {
    CertTypes[CertTypes["root"] = 0] = "root";
    CertTypes[CertTypes["intermediate"] = 1] = "intermediate";
    CertTypes[CertTypes["leaf"] = 2] = "leaf";
    CertTypes[CertTypes["key"] = 3] = "key";
})(CertTypes || (CertTypes = {}));
class CertError extends Error {
    constructor(status, message) {
        super(message);
        this._status = status;
    }
    get status() { return this._status; }
    set status(value) { this._status = value; }
}
class WebServer {
    static createWebServer(port, dataPath) {
        if (!WebServer.instance) {
            WebServer.instance = new WebServer(port, dataPath);
        }
        return WebServer.instance;
    }
    static getWebServer() {
        return WebServer.instance;
    }
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    constructor(port, dataPath) {
        this.DB_NAME = 'certs.db';
        this._app = (0, express_1.default)();
        this._port = port;
        this._dataPath = dataPath;
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
        this._app.set('views', path_1.default.join(__dirname, 'web/views'));
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
                console.log('Failed to initialize the database: ' + err.message);
                process.exit(4);
            }
            this._app.use((0, serve_favicon_1.default)(path_1.default.join(__dirname, "web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
            // this._app.use(Express.json);
            this._app.use(express_1.default.text({ type: 'text/plain' }));
            // this._app.use(Express.static("styles"));
            // this._app.use('/magnificpopup', Express.static(path.join(__dirname, 'web/magnific')))
            this._app.use('/scripts', express_1.default.static(path_1.default.join(__dirname, 'web/scripts')));
            this._app.use('/styles', express_1.default.static(path_1.default.join(__dirname, 'web/styles')));
            this._app.use('/icons', express_1.default.static(path_1.default.join(__dirname, 'web/icons')));
            this._app.use('/files', express_1.default.static(path_1.default.join(__dirname, 'web/files')));
            this._app.use('/images', express_1.default.static(path_1.default.join(__dirname, 'web/images')));
            this._app.use((req, _res, next) => {
                console.log(`${req.method} ${req.url}`);
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
                        let certString = yield this._tryAddCertificate(tempName);
                        return res.status(200).json(certString);
                    }
                    catch (err) {
                        return res.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).send(err.message);
                    }
                }));
            }));
            this._app.post('/uploadKey', ((req, res) => {
                if (!req.files || Object.keys(req.files).length == 0) {
                    return res.status(400).send('No file selected');
                }
                let keyFile = req.files.keyfile;
                let tempName = path_1.default.join(this._workPath, keyFile.name);
                keyFile.mv(tempName, (err) => __awaiter(this, void 0, void 0, function* () {
                    var _a;
                    if (err)
                        return res.status(500).send(err);
                    try {
                        let keyString = yield this._tryAddKey(tempName);
                        return res.status(200).json(keyString);
                    }
                    catch (err) {
                        return res.status((_a = err.status) !== null && _a !== void 0 ? _a : 500).send(err.message);
                    }
                }));
            }));
            this._app.get("/", (_request, response) => {
                response.render('index', { title: 'Certificates Management Home' });
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
                    let certString = yield this._tryAddCertificate(path_1.default.join(this._workPath, 'upload.pem'));
                    return response.status(200).json(certString);
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
                    let keyString = yield this._tryAddKey(path_1.default.join(this._workPath, 'upload.key'));
                    return response.status(200).json(keyString);
                }
                catch (err) {
                    response.status(500).send(err.message);
                }
            }));
            http_1.default.createServer(this._app).listen(this._port, '0.0.0.0');
            // this._app.listen(this._port, () => {
            //     console.log(`Listen on the port ${WebServer.getWebServer().port}...`);
            // });
            console.log('Starting');
        });
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
    _getKeyBrief(r) {
        return {
            name: r.name,
            certPair: (r.pairSerial == null) ? 'Not present' : r.name.substring(0, r.name.length - 4),
        };
    }
    _dbInit() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let files;
                    let certRows = this._certificates.chain().simplesort('name').data();
                    certRows.forEach((row) => {
                        if (!fs_1.default.existsSync(path_1.default.join(this._certificatesPath, row.name + '.pem'))) {
                            console.log(`Certificate ${row.name} not found - removed`);
                            this._certificates.remove(row);
                            this._certificates.chain().find({ 'serialNumber': row.signedBy }).update((r) => {
                                r.serialNumber = null;
                                console.log(`Removed signedBy from ${r.name}`);
                            });
                            this._privateKeys.chain().find({ pairSerial: row.serialNumber }).update((k) => {
                                k.pairSerial = null;
                                console.log(`Removed relationship to private key from ${k.name}`);
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
                    let addresults = yield Promise.all(adding);
                    console.log(addresults.join(';'));
                    let caList = this._certificates.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
                    let nonRoot = this._certificates.find({ '$and': [{ 'type': { '$ne': CertTypes.root } }, { signedBy: null }] });
                    // let nonRoot = certificates.chain().find({ 'type': certTypes.root }).find({ 'signedBy': null });
                    for (let i = 0; i < nonRoot.length; i++) {
                        let signer = yield this._findSigner(caList, node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, nonRoot[i].name + '.pem'), { encoding: 'utf8' })));
                        if (signer != -1) {
                            console.log(`${nonRoot[i].name} is signed by ${caList[signer].name}`);
                            nonRoot[i].signedBy = caList[signer].serialNumber;
                            this._certificates.update(nonRoot[i]);
                        }
                    }
                    let keyRows = this._privateKeys.chain().simplesort('name').data();
                    keyRows.forEach((key) => {
                        if (!(0, node_fs_1.existsSync)(path_1.default.join(this._privatekeysPath, key.name + '.pem'))) {
                            console.log(`Key ${key.name} not found - removed`);
                            this._privateKeys.remove(key);
                        }
                    });
                    files = fs_1.default.readdirSync(this._privatekeysPath);
                    adding = [];
                    files.forEach((file) => __awaiter(this, void 0, void 0, function* () {
                        console.log(path_1.default.basename(file));
                        let key = this._privateKeys.findOne({ name: path_1.default.parse(file).name });
                        if (!key) {
                            try {
                                adding.push(this._tryAddKey(path_1.default.join(this._privatekeysPath, file)));
                            }
                            catch (err) { }
                        }
                    }));
                    addresults = yield Promise.all(adding);
                    console.log(addresults.join(';'));
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
                            console.log('Not ' + caList[i].name);
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
                                retVal.push(s.name);
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
    _tryAddKey(filename) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log(`Trying to add ${path_1.default.basename(filename)}`);
            if (!fs_1.default.existsSync(filename)) {
                let err = new CertError(404, `${path_1.default.basename(filename)} does not exist`);
                throw err;
            }
            try {
                let k = node_forge_1.pki.privateKeyFromPem(fs_1.default.readFileSync(filename, { encoding: 'utf8' }));
                let krow = { e: k.e, n: k.n, pairSerial: null, name: null };
                let keys = this._privateKeys.find();
                let publicKey = node_forge_1.pki.setRsaPublicKey(k.e, k.n);
                for (let i = 0; i < keys.length; i++) {
                    if (this._isIdenticalKey(node_forge_1.pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                        throw new CertError(409, `Key already present: ${keys[i].name}`);
                    }
                }
                let certs = this._certificates.find();
                let newfile = 'unknown_key_';
                console.log(certs.length);
                for (let i = 0; i < certs.length; i++) {
                    if (this._isSignedBy(yield this._cache.getCertificate(certs[i].name), k.n, k.e)) {
                        krow.pairSerial = certs[i].serialNumber;
                        newfile = certs[i].name + '_key';
                        break;
                    }
                }
                if (krow.pairSerial == null) {
                    for (let i = 0; true; i++) {
                        if (!fs_1.default.existsSync(path_1.default.join(this._privatekeysPath, newfile + i.toString() + '.pem'))) {
                            newfile = newfile + i.toString();
                            break;
                        }
                    }
                }
                console.log(`Renamed ${path_1.default.basename(filename)} to ${newfile}.pem`);
                fs_1.default.renameSync(filename, path_1.default.join(this._privatekeysPath, newfile + '.pem'));
                krow.name = newfile;
                this._privateKeys.insert(krow);
                return 'key';
            }
            catch (err) {
                console.error(err.message);
                if (!err.status) {
                    err.status = 500;
                }
                throw err;
            }
        });
    }
    _tryAddCertificate(filename) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                var _a, _b;
                console.log(`Trying to add ${path_1.default.basename(filename)}`);
                if (!fs_1.default.existsSync(filename)) {
                    let err = new CertError(404, `${path_1.default.basename(filename)} does not exist`);
                    throw err;
                }
                try {
                    let c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(filename, { encoding: 'utf8' }));
                    let type;
                    let signedBy = null;
                    let havePrivateKey = false;
                    if (this._certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                        throw new CertError(409, `${path_1.default.basename(filename)} serial number ${c.serialNumber} is a duplicate - ignored`);
                    }
                    if (c.isIssuer(c)) {
                        type = CertTypes.root;
                        signedBy = c.serialNumber;
                    }
                    else {
                        let bc = c.getExtension('basicConstraints');
                        if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                            type = CertTypes.intermediate;
                        }
                        else {
                            type = CertTypes.leaf;
                        }
                        let caList = this._certificates.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
                        let signer = yield this._findSigner(caList, c);
                        let signeeList = this._certificates.find({ 'type': { '$in': [CertTypes.leaf, CertTypes.intermediate] } });
                        let list = yield this._findSigned(signeeList, c);
                        if (list.length > 0) {
                            list.forEach((l) => console.log(`${l} marked signed by new certificate`));
                        }
                        if (signer != -1) {
                            signedBy = caList[signer].serialNumber;
                        }
                    }
                    let name = (c.subject.getField('CN').value).replace(/ /g, '_');
                    if (name + '.pem' != path_1.default.basename(filename)) {
                        if (fs_1.default.existsSync(path_1.default.join(path_1.default.dirname(filename), name + '.pem'))) {
                            for (let i = 1; true; i++) {
                                if (!fs_1.default.existsSync(path_1.default.join(path_1.default.dirname(filename), name + '_' + i.toString() + '.pem'))) {
                                    name = name + '_' + i.toString();
                                    break;
                                }
                            }
                        }
                        console.log(`Renamed ${path_1.default.basename(filename)} to ${name}.pem`);
                        fs_1.default.renameSync(filename, path_1.default.join(this._certificatesPath, name + '.pem'));
                        let keys = this._privateKeys.chain().find({ pairSerial: null }).data();
                        for (let i = 0; i < keys.length; i++) {
                            if (this._isSignedBy(c, keys[i].n, keys[i].e)) {
                                console.log('Found private key for ' + name);
                                havePrivateKey = true;
                                fs_1.default.renameSync(path_1.default.join(this._privatekeysPath, keys[i].name + '.pem'), path_1.default.join(this._privatekeysPath, name + '_key.pem'));
                                this._privateKeys.chain().find({ name: keys[i].name }).update((row) => {
                                    row.name = name;
                                    row.pairSerial = c.serialNumber;
                                });
                            }
                        }
                    }
                    console.log(`Certificate ${name} added`);
                    this._certificates.insert({
                        name: name,
                        type: type,
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
                    resolve(CertTypes[type]);
                }
                catch (err) {
                    console.error(err.message);
                    if (!err.status) {
                        err.status = 500;
                    }
                    reject(err);
                }
            }));
        });
    }
}
exports.WebServer = WebServer;
WebServer.instance = null;
//# sourceMappingURL=webserver.js.map