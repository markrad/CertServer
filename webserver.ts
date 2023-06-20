import { PathLike, existsSync, mkdirSync, writeFileSync } from 'node:fs';
// import { exists } from 'node:fs/promises';
import path from 'path';
import http from 'http';
import fs from 'fs';

import { jsbn, pki } from 'node-forge'; 
import loki, { Collection, LokiFsAdapter } from 'lokijs'
import Express from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';

import { CertificateCache } from './certificateCache';
import { EventWaiter } from './eventWaiter';

enum CertTypes {
    root,
    intermediate,
    leaf,
    key
}

type CertificateSubject = {
    C: string,
    ST: string,
    L: string,
    O: string,
    OU: string,
    CN: string
}

type CertificateRow = {
    name: string, 
    type: CertTypes, 
    serialNumber: string, 
    publicKey: any, 
    privateKey: string,
    signedBy: any;
    issuer: CertificateSubject,
    subject: CertificateSubject,
    notBefore: Date,
    notAfter: Date,
    havePrivateKey: boolean,
};

type PrivateKeyRow = {
    n: jsbn.BigInteger,
    e: jsbn.BigInteger,
    pairSerial: string,
    name: string;
};

type CertificateBrief = {
    certType: string,
    name: string,
    issuer: CertificateSubject,
    subject: CertificateSubject,
    validFrom: Date,
    validTo: Date,
    signer: string,
    keyPresent: string,
    serialNumber: string,
}

type KeyBrief = {
    name: string,
    certPair: string,
}

class CertError extends Error {
    private _status: number;
    constructor(status: number, message: string) {
        super(message);
        this._status = status;
    }
    get status() { return this._status; }
    set status(value) { this._status = value; }
}

export class WebServer {
    static instance: WebServer = null;
    static createWebServer(port: number, dataPath: string): WebServer {
        if (!WebServer.instance) {
            WebServer.instance = new WebServer(port, dataPath);
        }

        return WebServer.instance;
    }
    static getWebServer(): WebServer {
        return WebServer.instance;
    }
    private readonly DB_NAME = 'certs.db';
    private _port: number;
    private _dataPath: PathLike;
    private _certificatesPath: string;
    private _privatekeysPath: string;
    private _workPath: string;
    private _dbPath: string;
    private _app: Express.Application = Express();
    private _db: loki;
    private _certificates: Collection<CertificateRow>;
    private _privateKeys: Collection<PrivateKeyRow>;
    private _cache: CertificateCache;
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    private constructor(port: number, dataPath: string) {
        this._port = port;
        this._dataPath = dataPath;
        this._certificatesPath = path.join(this._dataPath, 'certificates');
        this._privatekeysPath = path.join(this._dataPath, 'privatekeys');
        this._workPath = path.join(this._dataPath, 'work');
        this._dbPath = path.join(this._dataPath, 'db');

        if (!existsSync(this._dataPath))
            mkdirSync(this._dataPath, { recursive: true });
        if (!existsSync(this._certificatesPath)) 
            mkdirSync(this._certificatesPath);
        if (!existsSync(this._privatekeysPath)) 
            mkdirSync(this._privatekeysPath);
        if (!existsSync(this._workPath)) 
            mkdirSync(this._workPath);
        if (!existsSync(this._dbPath)) 
            mkdirSync(this._dbPath);

        this._cache = new CertificateCache(this._certificatesPath, 10 * 60 * 60);
        this._app.set('views', path.join(__dirname, 'web/views'));
        this._app.set('view engine', 'pug');
    }

    async start() {
        
        let getCollections: () => void = () => {
            if (null == (certificates = db.getCollection<CertificateRow>('certificates'))) {
                certificates = db.addCollection<CertificateRow>('certificates', { });
            }
            if (null == (privateKeys = db.getCollection<PrivateKeyRow>('privateKeys'))) {
                privateKeys = db.addCollection<PrivateKeyRow>('privateKeys', { });
            }

        ew.EventSet();
    }

        try {
            var ew = new EventWaiter();
            var certificates: Collection<CertificateRow> = null;
            var privateKeys: Collection<PrivateKeyRow> = null;
            var db = new loki(path.join(this._dbPath.toString(), this.DB_NAME), { 
                autosave: true, 
                autosaveInterval: 2000, 
                adapter: new LokiFsAdapter(),
                autoload: true,
                autoloadCallback: getCollections,
                verbose: true,
                persistenceMethod: 'fs'
            });
            await ew.EventWait();
            this._db = db;
            this._certificates = certificates;
            this._privateKeys = privateKeys;
            await this._dbInit();
        }
        catch (err) {
            console.log('Failed to initialize the database: ' + err.message);
            process.exit(4);
        }
        this._app.use(serveFavicon(path.join(__dirname, "web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
        // this._app.use(Express.json);
        this._app.use(Express.text({ type: 'text/plain' }));
        // this._app.use(Express.static("styles"));
        // this._app.use('/magnificpopup', Express.static(path.join(__dirname, 'web/magnific')))
        this._app.use('/scripts', Express.static(path.join(__dirname, 'web/scripts')))
        this._app.use('/styles', Express.static(path.join(__dirname, 'web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, 'web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, 'web/files')));
        this._app.use('/images', Express.static(path.join(__dirname, 'web/images')));
        this._app.use((req, _res, next) => {
            console.log(`${req.method} ${req.url}`);
            next();
        });
        this._app.use(FileUpload());
        this._app.post('/uploadCert', ((req: any, res) => {
            if (!req.files || Object.keys(req.files).length == 0) {
                return res.status(400).send('No file selected');
            }
            let certfile = req.files.certFile;
            let tempName = path.join(this._workPath, certfile.name);
            certfile.mv(tempName, async (err: Error) => {
                if (err)
                    return res.status(500).send(err);

                try {
                    let certString = await this._tryAddCertificate(tempName);
                    return res.status(200).json(certString);
                }
                catch (err) {
                    return res.status(err.status?? 500).send(err.message);
                }
            });
        }));
        this._app.post('/uploadKey', ((req: any, res) => {
            if (!req.files || Object.keys(req.files).length == 0) {
                return res.status(400).send('No file selected');
            }
            let keyFile = req.files.keyfile;
            let tempName = path.join(this._workPath, keyFile.name);
            keyFile.mv(tempName, async (err: Error) => {
                if (err) return res.status(500).send(err);

                try {
                    let keyString = await this._tryAddKey(tempName);
                    return res.status(200).json(keyString);
                }
                catch (err) {
                    return res.status(err.status ?? 500).send(err.message);
                }
            });
        }));
        this._app.get("/", (_request, response) => {
            response.render('index', { title: 'Certificates Management Home'});
        });
        this._app.get("/certlist", (request, response) => {
            let type: CertTypes = CertTypes[(request.query.type as any)] as unknown as any;

            if (type == undefined) {
                response.status(404).send(`Directory ${request.query.type} not found`);
            }
            else {
                let retVal: any = {};
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
        this._app.get("/certdetails", async (request, response) => {
            let filename = path.join(this._certificatesPath, request.query.name + '.pem');
            if (!existsSync(filename)) response.status(404);
            let c = this._certificates.findOne({ name: request.query.name as unknown as string });
            if (c) {
                let retVal: CertificateBrief = this._getCertificateBrief(c);
                response.status(200).json(retVal);
            }
            else {
                response.status(500).send('This should not happen');
            }
        });
        this._app.get("/keydetails", async (request, response) => {
            let filename = path.join(this._privatekeysPath, request.query.name + '.pem');
            if (!existsSync(filename)) response.status(404);
            let k = this._privateKeys.findOne({ name: request.query.name as unknown as string });
            if (k) {
                let retVal: KeyBrief = this._getKeyBrief(k);
                response.status(200).json(retVal);
            }
            else {
                response.status(500).send('This should not happen');
            }
        });
        this._app.post('/api/uploadCert', async (request, response) => {
            if (!(request.body as string).includes('\n')) {
                return response.status(400).send('Certificate must be in standard 64 byte line length format - try --data-binary on curl');
            }
            try {
                writeFileSync(path.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                let certString = await this._tryAddCertificate(path.join(this._workPath, 'upload.pem'));
                return response.status(200).json(certString);
            }
            catch (err) {
                response.status(500).send(err.message);
            }
        });
        this._app.post('/api/uploadKey', async (request, response) => {
            if (!(request.body as string).includes('\n')) {
                return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary on curl');
            }
            try {
                writeFileSync(path.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                let keyString = await this._tryAddKey(path.join(this._workPath, 'upload.key'));
                return response.status(200).json(keyString);
            }
            catch (err) {
                response.status(500).send(err.message);
            }
        });

        http.createServer(this._app).listen(this._port, '0.0.0.0');
        // this._app.listen(this._port, () => {
        //     console.log(`Listen on the port ${WebServer.getWebServer().port}...`);
        // });
        console.log('Starting');
    }

    private _getSubject(s: pki.Certificate['issuer'] | pki.Certificate['subject']): CertificateSubject {
        let getValue: (v: string) => string = (v: string): string => {
            let work = s.getField(v);
            return work? work.value : null;
        }
        return {
            C: getValue('C'),
            ST: getValue('ST'),
            L: getValue('L'),
            O: getValue('O'),
            OU: getValue('OU'),
            CN: getValue('CN')
        }
    }

    private _getCertificateBrief(r: CertificateRow): CertificateBrief {
        let signer = (r.signedBy == null)? null : this._certificates.findOne({ serialNumber: r.signedBy }).name;
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
            keyPresent: key != null? 'yes' : 'no',
            // TODO: Add reference to signer
         };
    }

    private _getKeyBrief(r: PrivateKeyRow): KeyBrief {
        return {
            name: r.name,
            certPair: (r.pairSerial == null)? 'Not present' : r.name.substring(0, r.name.length -4),
        }
    }

    private async _dbInit(): Promise<void> {
        return new Promise<void>(async (resolve, reject) => {
            try {
                let files: string[];
                let certRows: CertificateRow[] = this._certificates.chain().simplesort('name').data();

                certRows.forEach((row: CertificateRow) => {
                    if (!fs.existsSync(path.join(this._certificatesPath, row.name + '.pem'))) {
                        console.log(`Certificate ${row.name} not found - removed`);
                        this._certificates.remove(row);
                        this._certificates.chain().find({'serialNumber': row.signedBy }).update((r) => {
                            r.serialNumber = null;
                            console.log(`Removed signedBy from ${r.name}`);
                        });
                        this._privateKeys.chain().find({ pairSerial: row.serialNumber }).update((k) => {
                            k.pairSerial = null;
                            console.log(`Removed relationship to private key from ${k.name}`);
                        });
                    }
                });

                files = fs.readdirSync(this._certificatesPath);

                let adding: Promise<string>[] = [];

                files.forEach(async (file) => {
                    let cert = this._certificates.findOne({ name: path.parse(file).name });
                    if (!cert) {
                        try {
                            adding.push(this._tryAddCertificate(path.join(this._certificatesPath, file)));
                        }
                        catch (err) {}
                    }
                });

                let addresults: string[] = await Promise.all(adding);
                console.log(addresults.join(';'));

                let caList = this._certificates.find({ 'type': { '$in': [ CertTypes.root, CertTypes.intermediate ] }});
                let nonRoot = this._certificates.find( { '$and': [ { 'type': { '$ne': CertTypes.root }}, { signedBy: null } ] });
                // let nonRoot = certificates.chain().find({ 'type': certTypes.root }).find({ 'signedBy': null });

                for (let i: number = 0; i < nonRoot.length; i++) {
                    let signer = await this._findSigner(caList, pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, nonRoot[i].name + '.pem'), { encoding: 'utf8' })));
                    if (signer != -1) {
                        console.log(`${nonRoot[i].name} is signed by ${caList[signer].name}`);
                        nonRoot[i].signedBy = caList[signer].serialNumber;
                        this._certificates.update(nonRoot[i]);
                    }
                }

                let keyRows: PrivateKeyRow[] = this._privateKeys.chain().simplesort('name').data();

                keyRows.forEach((key) => {
                    if (!existsSync(path.join(this._privatekeysPath, key.name + '.pem'))) {
                        console.log(`Key ${key.name} not found - removed`);
                        this._privateKeys.remove(key);
                    }
                });

                files = fs.readdirSync(this._privatekeysPath);

                adding = [];
                files.forEach(async (file) => {
                    console.log(path.basename(file));
                    let key = this._privateKeys.findOne({ name: path.parse(file).name });
                    if (!key) {
                        try {
                            adding.push(this._tryAddKey(path.join(this._privatekeysPath, file)));
                        }
                        catch (err) {}
                    }
                });

                addresults = await Promise.all(adding);
                console.log(addresults.join(';'));

                this._db.saveDatabase((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }
            catch (err) {
                reject(err);
            }
        });
    }

    private async _findSigner(caList: CertificateRow[], certificate: pki.Certificate): Promise<number> {
        return new Promise<number>(async(resolve, _reject) => {
            if (caList) {
                for (let i = 0; i < caList.length; i++) {
                    try {
                        let c = await this._cache.getCertificate(caList[i].name);
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
        })
    }

    private async _findSigned(signeeList: CertificateRow[], certificate: pki.Certificate): Promise<string[]> {
        return new Promise<string[]>(async (resolve, reject) => {
            let retVal: string[] = [];
            try {
                signeeList.forEach(async (s) => {
                    let check = await this._cache.getCertificate(s.name);
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
                });
                resolve(retVal);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    _isSignedBy(cert: pki.Certificate, keyn: jsbn.BigInteger, keye: jsbn.BigInteger): boolean {
        let publicKey = pki.setRsaPublicKey(keyn, keye);
        let certPublicKey: pki.rsa.PublicKey = cert.publicKey as pki.rsa.PublicKey;

        return this._isIdenticalKey(publicKey, certPublicKey);
        // if (publicKey.n.data.length != certPublicKey.n.data.length) return false;

        // for (let i = 0; i < publicKey.n.data.length; i++) {
        //     if (publicKey.n.data[i] != certPublicKey.n.data[i]) {
        //         return false;
        //     }
        // }

        // return true;
    }

    _isIdenticalKey(leftKey: pki.rsa.PublicKey, rightKey: pki.rsa.PublicKey): boolean {
        if (leftKey.n.data.length != rightKey.n.data.length) {
            return false;
        }

        for (let i = 0; i < leftKey.n.data.length; i++) {
            if (leftKey.n.data[i] != rightKey.n.data[i]) return false;
        }

        return true;
    }

    private async _tryAddKey(filename: string): Promise<string> {
        console.log(`Trying to add ${path.basename(filename)}`);
        if (!fs.existsSync(filename)) {
            let err = new CertError(404, `${path.basename(filename)} does not exist`)
            throw err;
        }

        try {
            let k = pki.privateKeyFromPem(fs.readFileSync(filename, { encoding: 'utf8' }));
            let krow: PrivateKeyRow = { e: k.e, n: k.n, pairSerial: null, name: null };
            let keys = this._privateKeys.find();
            let publicKey = pki.setRsaPublicKey(k.e, k.n);

            for (let i = 0; i < keys.length; i++) {
                if (this._isIdenticalKey(pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                    throw new CertError(409, `Key already present: ${keys[i].name}`);
                }
            }
            
            let certs = this._certificates.find();
            let newfile = 'unknown_key_';

            console.log(certs.length);
            for (let i = 0; i < certs.length; i++) {
                if (this._isSignedBy(await this._cache.getCertificate(certs[i].name), k.n, k.e)) {
                    krow.pairSerial = certs[i].serialNumber;
                    newfile = certs[i].name + '_key';
                    break;
                }
            }

            if (krow.pairSerial == null) {
                for (let i = 0; true; i++) {
                    if (!fs.existsSync(path.join(this._privatekeysPath, newfile + i.toString() + '.pem'))) {
                        newfile = newfile + i.toString();
                        break;
                    }
                }
            }

            console.log(`Renamed ${path.basename(filename)} to ${newfile}.pem`)
            fs.renameSync(filename, path.join(this._privatekeysPath, newfile + '.pem'));
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
    }

    private async _tryAddCertificate(filename: string): Promise<string> {
        return new Promise<string>(async (resolve, reject) => {
            console.log(`Trying to add ${path.basename(filename)}`);
            if (!fs.existsSync(filename)) {
                let err = new CertError(404, `${path.basename(filename)} does not exist`)
                throw err;
            }

            try {
                let c: pki.Certificate = pki.certificateFromPem(fs.readFileSync(filename, { encoding: 'utf8' }));
                let type: CertTypes;
                let signedBy: string = null;
                let havePrivateKey: boolean = false;

                if (this._certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                    throw new CertError(409, `${path.basename(filename)} serial number ${c.serialNumber} is a duplicate - ignored`);
                }

                if (c.isIssuer(c)) {
                    type = CertTypes.root;
                    signedBy = c.serialNumber ;
                }
                else {
                    let bc: any = c.getExtension('basicConstraints');

                    if ((bc != null) && (bc.cA ?? false) == true && (bc.pathlenConstraint ?? 1) > 0) {
                        type = CertTypes.intermediate;
                    }
                    else {
                        type = CertTypes.leaf;
                    }

                    let caList = this._certificates.find({ 'type': { '$in': [ CertTypes.root, CertTypes.intermediate ] }});
                    let signer = await this._findSigner(caList, c);
                    let signeeList = this._certificates.find({ 'type': { '$in': [ CertTypes.leaf, CertTypes.intermediate ] }});
                    let list: string[] = await this._findSigned(signeeList, c);

                    if (list.length > 0) {
                        list.forEach((l) => console.log(`${l} marked signed by new certificate`));
                    }

                    if (signer != -1) {
                        signedBy = caList[signer].serialNumber;
                    }
                }

                let name = (c.subject.getField('CN').value).replace(/ /g, '_');

                if (name + '.pem' != path.basename(filename)) {
                    if (fs.existsSync(path.join(path.dirname(filename), name + '.pem'))) {
                        for (let i = 1; true; i++) {
                            if (!fs.existsSync(path.join(path.dirname(filename), name + '_' + i.toString() + '.pem'))) {
                                name = name + '_' + i.toString();
                                break;
                            }
                        }
                    }
                    console.log(`Renamed ${path.basename(filename)} to ${name}.pem`)
                    fs.renameSync(filename, path.join(this._certificatesPath, name + '.pem'));

                    let keys: (PrivateKeyRow & LokiObj)[] = this._privateKeys.chain().find({ pairSerial: null }).data();

                    for (let i = 0; i < keys.length; i++) {
                        if (this._isSignedBy(c, keys[i].n, keys[i].e)) {
                            console.log('Found private key for ' + name);
                            havePrivateKey = true;
                            fs.renameSync(path.join(this._privatekeysPath, keys[i].name + '.pem'), path.join(this._privatekeysPath, name + '_key.pem'));
                            this._privateKeys.chain().find({ name: keys[i].name }).update((row) => {
                                row.name = name;
                                row.pairSerial = c.serialNumber;
                            })
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
        });
    } 
}