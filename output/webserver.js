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
exports.WebServer = void 0;
const node_fs_1 = require("node:fs");
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const node_forge_1 = require("node-forge");
const lokijs_1 = __importDefault(require("lokijs"));
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const serve_favicon_1 = __importDefault(require("serve-favicon"));
const certificateCache_1 = require("./certificateCache");
var certTypes;
(function (certTypes) {
    certTypes[certTypes["root"] = 0] = "root";
    certTypes[certTypes["intermediate"] = 1] = "intermediate";
    certTypes[certTypes["leaf"] = 2] = "leaf";
})(certTypes || (certTypes = {}));
class CertError extends Error {
    constructor(status, message) {
        super(message);
        this._status = status;
    }
    get status() { return this._status; }
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
        if (!(0, node_fs_1.existsSync)(this._dataPath))
            (0, node_fs_1.mkdir)(this._dataPath, { recursive: true }, (err) => { throw err; });
        this._certificatesPath = path_1.default.join(this._dataPath, 'certificates');
        this._cache = new certificateCache_1.CertificateCache(this._certificatesPath, 10 * 60 * 60);
        // this._rootsPath = path.join(this._dataPath.toString(), 'roots');
        // this._intermediatesPath = path.join(this._dataPath.toString(), 'intermediates');
        // this._leavesPath = path.join(this._dataPath.toString(), 'leaves');
        this._privatekeysPath = path_1.default.join(this._dataPath, 'privatekeys');
        this._workPath = path_1.default.join(this._dataPath, 'work');
        this._dbPath = path_1.default.join(this._dataPath, 'db');
        if (!(0, node_fs_1.existsSync)(this._certificatesPath))
            (0, node_fs_1.mkdir)(this._certificatesPath, (err) => { throw err; });
        // if (!existsSync(this._rootsPath)) 
        //     mkdir(this._rootsPath, (err) => { throw err });
        // if (!existsSync(this._intermediatesPath)) 
        //     mkdir(this._intermediatesPath, (err) => { throw err; });
        // if (!existsSync(this._leavesPath)) 
        //     mkdir(this._leavesPath, (err) => { throw err; });
        if (!(0, node_fs_1.existsSync)(this._privatekeysPath))
            (0, node_fs_1.mkdir)(this._privatekeysPath, (err) => { throw err; });
        if (!(0, node_fs_1.existsSync)(this._workPath))
            (0, node_fs_1.mkdir)(this._workPath, (err) => { throw err; });
        if (!(0, node_fs_1.existsSync)(this._dbPath))
            (0, node_fs_1.mkdir)(this._dbPath, (err) => { throw err; });
        this._app.set('views', path_1.default.join(__dirname, 'web/views'));
        this._app.set('view engine', 'pug');
    }
    start() {
        return __awaiter(this, void 0, void 0, function* () {
            let { certificates, privatekeys } = yield this._dbInit();
            this._certificates = certificates;
            this._privateKeys = privatekeys;
            this._app.use((0, serve_favicon_1.default)(path_1.default.join(__dirname, "web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
            // this._app.use(Express.static("styles"));
            this._app.use('/magnificpopup', express_1.default.static(path_1.default.join(__dirname, 'web/magnific')));
            this._app.use('/styles', express_1.default.static(path_1.default.join(__dirname, 'web/styles')));
            this._app.use('/icons', express_1.default.static(path_1.default.join(__dirname, 'web/icons')));
            this._app.use('/files', express_1.default.static(path_1.default.join(__dirname, 'web/files')));
            this._app.use((0, express_fileupload_1.default)());
            this._app.post('/upload', ((req, res) => {
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
                        this._tryAddCertificate(certificates, tempName);
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
                let type = request.query.type == 'roots'
                    ? certTypes.root
                    : request.query.type == 'intermediates'
                        ? certTypes.intermediate
                        : request.query.type == 'leaves'
                            ? certTypes.leaf
                            : null;
                if (type == null) {
                    response.status(404).send(`Directory ${request.query.type} not found`);
                }
                else {
                    let retVal = {};
                    retVal['files'] = certificates.chain().find({ type: type }).simplesort('name').data().map((entry) => entry.name);
                    response.status(200).json(retVal);
                }
            });
            this._app.get('/api/upload', (_request, response) => {
                response.status(404).send('Unknown');
            });
            this._app.listen(this._port, () => {
                console.log(`Listen on the port ${WebServer.getWebServer().port}...`);
            });
            console.log('Starting');
        });
    }
    _dbInit() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let certificates = null;
                    this._db = new lokijs_1.default(path_1.default.join(this._dbPath.toString(), this.DB_NAME), { autosave: true, autoload: true, });
                    if (null == (certificates = this._db.getCollection('certificates'))) {
                        certificates = this._db.addCollection('certificates', {});
                    }
                    let files;
                    let certRows = certificates.chain().simplesort('name').data();
                    certRows.forEach((row) => {
                        if (!fs_1.default.existsSync(row.name)) {
                            console.log(`Certificate ${row.name} not found - removed`);
                            certificates.remove(row);
                            certificates.chain().find({ 'serialNumber': row.signedBy }).update((r) => {
                                r.serialNumber = null;
                                console.log(`Removed signedBy from ${r.name}`);
                            });
                        }
                    });
                    files = fs_1.default.readdirSync(this._certificatesPath);
                    files.forEach((file) => {
                        let cert = certificates.findOne({ name: path_1.default.basename(file) });
                        if (!cert) {
                            try {
                                this._tryAddCertificate(certificates, path_1.default.join(this._certificatesPath, file));
                            }
                            catch (err) { }
                        }
                    });
                    let caList = certificates.find({ 'type': { '$containsAny': [certTypes.root, certTypes.intermediate] } });
                    let nonRoot = certificates.find({ '$and': [{ 'type': { '$ne': certTypes.root } }, { signedBy: null }] });
                    // let nonRoot = certificates.chain().find({ 'type': certTypes.root }).find({ 'signedBy': null });
                    for (let i = 0; i < nonRoot.length; i++) {
                        let signer = yield this._findSigner(caList, node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(path_1.default.join(this._certificatesPath, nonRoot[i].name), { encoding: 'utf8' })));
                        if (signer != -1) {
                            console.log(`${nonRoot[i].name} is signed by ${caList[signer].name}`);
                            nonRoot[i].signedBy = caList[signer].serialNumber;
                            certificates.update(nonRoot[i]);
                        }
                    }
                    resolve({ certificates: certificates, privatekeys: null });
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    _findSigner(caList, certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            for (let i = 0; i < caList.length; i++) {
                if ((yield this._cache.getCertificate(caList[i].name)).verify(certificate)) {
                    return i;
                }
            }
            return -1;
        });
    }
    _findSigned(certificate) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let retVal = [];
                try {
                    let signeeList = this._certificates.find({ 'type': { '$containsAny': [certTypes.leaf, certTypes.intermediate] } });
                    signeeList.forEach((s) => __awaiter(this, void 0, void 0, function* () {
                        let check = yield this._cache.getCertificate(s.name);
                        if (certificate.verify(check)) {
                            this._certificates.chain().find({ 'serialNumber': check.serialNumber }).update((u) => {
                                u.signedBy = certificate.serialNumber;
                            });
                            retVal.push(s.name);
                            this._cache.markDirty(s.name);
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
    _tryAddCertificate(certificates, filename) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            console.log(`Trying to add ${path_1.default.basename(filename)}`);
            if (!fs_1.default.existsSync(filename)) {
                let err = new CertError(404, `${path_1.default.basename(filename)} does not exist`);
                throw err;
            }
            try {
                let c = node_forge_1.pki.certificateFromPem(fs_1.default.readFileSync(filename, { encoding: 'utf8' }));
                let type;
                let signedBy = null;
                if (certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                    throw new CertError(409, `${path_1.default.basename(filename)} is a duplicate - ignored`);
                }
                if (c.isIssuer(c)) {
                    type = certTypes.root;
                    signedBy = c.signature;
                }
                else {
                    let bc = c.getExtension('basicConstraints');
                    if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                        type = certTypes.intermediate;
                    }
                    else {
                        type = certTypes.leaf;
                    }
                    let caList = certificates.find({ 'type': { '$containsAny': [certTypes.root, certTypes.intermediate] } });
                    let signer = yield this._findSigner(caList, c);
                    let list = yield this._findSigned(c);
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
                }
                console.log(`Certificate ${name} added`);
                certificates.insert({ name: name, type: type, serialNumber: c.serialNumber, publicKey: c.publicKey, privateKey: null, signedBy: signedBy });
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
}
WebServer.instance = null;
exports.WebServer = WebServer;
//# sourceMappingURL=webserver.js.map