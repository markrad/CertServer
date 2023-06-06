import { PathLike, existsSync, mkdir } from 'node:fs';
import path from 'path';
import http from 'http';
import fs from 'fs';
import { pki } from 'node-forge'; 
import loki, { Collection } from 'lokijs'
import Express from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';

import { CertificateCache } from './certificateCache';

enum certTypes {
    root,
    intermediate,
    leaf
}

type certificateRow = {
    name: string, 
    type: certTypes, 
    serialNumber: string, 
    publicKey: any, 
    privateKey: string,
    signedBy: any;
};

class CertError extends Error {
    private _status: number;
    constructor(status: number, message: string) {
        super(message);
        this._status = status;
    }
    get status() { return this._status }
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
    // private _rootsPath: PathLike;
    // private _intermediatesPath: PathLike;
    // private _leavesPath: PathLike;
    private _privatekeysPath: string;
    private _workPath: string;
    private _dbPath: string;
    private _app: Express.Application = Express();
    private _db: loki;
    private _certificates: Collection<certificateRow>;
    private _privateKeys: Collection;
    private _cache: CertificateCache;
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    private constructor(port: number, dataPath: string) {
        this._port = port;
        this._dataPath = dataPath;

        if (!existsSync(this._dataPath)) mkdir(this._dataPath, { recursive: true }, (err) => { throw err; });
        this._certificatesPath = path.join(this._dataPath, 'certificates');
        this._cache = new CertificateCache(this._certificatesPath, 10 * 60 * 60);
        // this._rootsPath = path.join(this._dataPath.toString(), 'roots');
        // this._intermediatesPath = path.join(this._dataPath.toString(), 'intermediates');
        // this._leavesPath = path.join(this._dataPath.toString(), 'leaves');
        this._privatekeysPath = path.join(this._dataPath, 'privatekeys');
        this._workPath = path.join(this._dataPath, 'work');
        this._dbPath = path.join(this._dataPath, 'db');
        if (!existsSync(this._certificatesPath)) 
            mkdir(this._certificatesPath, (err) => { throw err });
        // if (!existsSync(this._rootsPath)) 
        //     mkdir(this._rootsPath, (err) => { throw err });
        // if (!existsSync(this._intermediatesPath)) 
        //     mkdir(this._intermediatesPath, (err) => { throw err; });
        // if (!existsSync(this._leavesPath)) 
        //     mkdir(this._leavesPath, (err) => { throw err; });
        if (!existsSync(this._privatekeysPath)) 
            mkdir(this._privatekeysPath, (err) => { throw err; });
        if (!existsSync(this._workPath)) 
            mkdir(this._workPath, (err) => { throw err; });
        if (!existsSync(this._dbPath)) 
            mkdir(this._dbPath, (err) => { throw err; });

        this._app.set('views', path.join(__dirname, 'web/views'));
        this._app.set('view engine', 'pug');
    }

    async start() {
        let { certificates, privatekeys } = await this._dbInit();
        this._certificates = certificates;
        this._privateKeys = privatekeys;
        this._app.use(serveFavicon(path.join(__dirname, "web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
        // this._app.use(Express.static("styles"));
        this._app.use('/magnificpopup', Express.static(path.join(__dirname, 'web/magnific')))
        this._app.use('/styles', Express.static(path.join(__dirname, 'web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, 'web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, 'web/files')));
        this._app.use(FileUpload());
        this._app.post('/upload', ((req: any, res) => {
            if (!req.files || Object.keys(req.files).length == 0) {
                return res.status(400).send('No file selected');
            }
            let certfile = req.files.certFile;
            let tempName = path.join(this._workPath, certfile.name);
            certfile.mv(tempName, async (err: Error) => {
                if (err)
                    return res.status(500).send(err);

                try {
                    this._tryAddCertificate(certificates, tempName);
                }
                catch (err) {
                    return res.status(err.status?? 500).send(err.message);
                }
            });
        }));
        this._app.get("/", (_request, response) => {
            response.render('index', { title: 'Certificates Management Home'});
        });
        this._app.get("/certlist", (request, response) => {
            let type: certTypes = request.query.type == 'roots'
                ? certTypes.root
                : request.query.type =='intermediates'
                ? certTypes.intermediate
                : request.query.type == 'leaves'
                ? certTypes.leaf
                : null;
            if (type == null) {
                response.status(404).send(`Directory ${request.query.type} not found`);
            }
            else {
                let retVal: any = {};
                retVal['files'] = certificates.chain().find({ type: type }).simplesort('name').data().map((entry) => entry.name);
                response.status(200).json(retVal);
            }
        });
        this._app.get('/api/upload', (_request, response) => {
            response.status(404).send('Unknown');
        });

        http.createServer(this._app).listen(this._port, '0.0.0.0');
        // this._app.listen(this._port, () => {
        //     console.log(`Listen on the port ${WebServer.getWebServer().port}...`);
        // });
        console.log('Starting');
    }

    private async _dbInit(): Promise<{ certificates: Collection<certificateRow>, privatekeys: Collection }> {
        return new Promise<{ certificates: Collection<certificateRow>, privatekeys: any }>(async (resolve, reject) => {
            try {
                let certificates: Collection<certificateRow> = null;

                this._db = new loki(path.join(this._dbPath.toString(), this.DB_NAME), { autosave: true, autoload: true, });
                
                if (null == (certificates = this._db.getCollection<certificateRow>('certificates'))) {
                    certificates = this._db.addCollection<certificateRow>('certificates', { });
                }
                let files: string[];
                let certRows: certificateRow[] = certificates.chain().simplesort('name').data();

                certRows.forEach((row: certificateRow) => {
                    if (!fs.existsSync(row.name)) {
                        console.log(`Certificate ${row.name} not found - removed`);
                        certificates.remove(row);
                        certificates.chain().find({'serialNumber': row.signedBy }).update((r) => {
                            r.serialNumber = null;
                            console.log(`Removed signedBy from ${r.name}`);
                        });
                    }
                });

                files = fs.readdirSync(this._certificatesPath);

                files.forEach((file) => {
                    let cert = certificates.findOne({ name: path.basename(file) });
                    if (!cert) {
                        try {
                            this._tryAddCertificate(certificates, path.join(this._certificatesPath, file));
                        }
                        catch (err) {}
                    }
                });

                let caList = certificates.find({ 'type': { '$containsAny': [ certTypes.root, certTypes.intermediate ] }});
                let nonRoot = certificates.find( { '$and': [ { 'type': { '$ne': certTypes.root }}, { signedBy: null } ] });
                // let nonRoot = certificates.chain().find({ 'type': certTypes.root }).find({ 'signedBy': null });

                for (let i: number = 0; i < nonRoot.length; i++) {
                    let signer = await this._findSigner(caList, pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, nonRoot[i].name), { encoding: 'utf8' })));
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
        });
    }

    private async _findSigner(caList: certificateRow[], certificate: pki.Certificate): Promise<number> {
        for (let i = 0; i < caList.length; i++) {
            if ((await this._cache.getCertificate(caList[i].name)).verify(certificate)) {
                return i;
            }
        }

        return -1;
    }

    private async _findSigned(certificate: pki.Certificate): Promise<string[]> {
        return new Promise<string[]>(async (resolve, reject) => {
            let retVal: string[] = [];
            try {
                let signeeList = this._certificates.find({ 'type': { '$containsAny': [ certTypes.leaf, certTypes.intermediate ] }});

                signeeList.forEach(async (s) => {
                    let check = await this._cache.getCertificate(s.name);
                    if (certificate.verify(check)) {
                        this._certificates.chain().find({ 'serialNumber': check.serialNumber }).update((u) => {
                            u.signedBy = certificate.serialNumber;
                        });
                        retVal.push(s.name);
                        this._cache.markDirty(s.name);
                    }
                });
                resolve(retVal);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    private async _tryAddCertificate(certificates: Collection<certificateRow>, filename: string): Promise<void> {
        console.log(`Trying to add ${path.basename(filename)}`);
        if (!fs.existsSync(filename)) {
            let err = new CertError(404, `${path.basename(filename)} does not exist`)
            throw err;
        }

        try {
            let c: pki.Certificate = pki.certificateFromPem(fs.readFileSync(filename, { encoding: 'utf8' }));
            let type: certTypes;
            let signedBy: string = null;

            if (certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                throw new CertError(409, `${path.basename(filename)} is a duplicate - ignored`);
            }

            if (c.isIssuer(c)) {
                type = certTypes.root;
                signedBy = c.signature;
            }
            else {
                let bc: any = c.getExtension('basicConstraints');

                if ((bc != null) && (bc.cA ?? false) == true && (bc.pathlenConstraint ?? 1) > 0) {
                    type = certTypes.intermediate;
                }
                else {
                    type = certTypes.leaf;
                }

                let caList = certificates.find({ 'type': { '$containsAny': [ certTypes.root, certTypes.intermediate ] }});
                let signer = await this._findSigner(caList, c);
                let list: string[] = await this._findSigned(c);

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
    } 

    // private async _getFiles(dir: string, prefix: string, serialNumber: string): Promise<string> {
    //     return new Promise<string>((resolve, reject) => {
    //         fs.readdir(dir, (err, files) => {
    //             if (err) reject(err);

    //             let filteredFiles = files.filter((name) => name.startsWith(prefix));
    //             let found = filteredFiles.findIndex((file) => {
    //                 let c = pki.certificateFromPem(fs.readFileSync(path.join(dir, file), { encoding: 'utf8'}));
    //                 return c.serialNumber == serialNumber;
    //             });

    //             if (found != -1)
    //                 resolve(null);
    //             else
    //                 resolve(filteredFiles.length == 0? prefix + '.pem' : prefix + '_' + filteredFiles.length.toString() + '.pem');
    //         });
    //     });
    // }
}