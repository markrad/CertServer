import { existsSync, mkdirSync/*, writeFileSync*/ } from 'node:fs';
// import { exists } from 'node:fs/promises';
import path from 'path';
import http from 'http';
import https from 'https';
import fs from 'fs';
//import * as fspromises from 'fs/promises'
import { /*access, constants,*/ readFile, writeFile, appendFile, copyFile, unlink, rename } from 'fs/promises'
import crypto from 'crypto';

import { jsbn, pki, pem, util, random, md } from 'node-forge'; 
import loki, { Collection, LokiFsAdapter } from 'lokijs'
import Express, { NextFunction } from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';
import WsServer from 'ws';
import * as log4js from 'log4js';

import { CertificateCache } from './certificateCache';
import { EventWaiter } from './utility/eventWaiter';
import { exists } from './utility/exists';
import { ExtensionParent } from './Extensions/ExtensionParent';
import { ExtensionBasicConstraints } from './Extensions/ExtensionBasicConstraints';
import { ExtensionKeyUsage } from './Extensions/ExtensionKeyUsage';
import { ExtensionAuthorityKeyIdentifier } from './Extensions/ExtensionAuthorityKeyIdentifier';
import { ExtensionSubjectKeyIdentifier } from './Extensions/ExtensionSubjectKeyIdentifier';
import { ExtensionExtKeyUsage } from './Extensions/ExtensionExtKeyUsage';
import { ExtensionSubjectAltName, ExtensionSubjectAltNameOptions } from './Extensions/ExtensionSubjectAltName';

type Config = {
    certServer: {
        port: number,
        root: string,
        certificate?: string,
        key?: string,
        subject: {
            C: string,
            ST: string,
            L: string,
            O: string,
            OU: string
        }
    }
};

enum CertTypes {
    cert,
    root,
    intermediate,
    leaf,
    key, 
}

type CertificateSubject = {
    C?: string,
    ST?: string,
    L?: string,
    O?: string,
    OU?: string,
    CN: string
}

type CertificateRow = {
    name: string, 
    type: CertTypes, 
    serialNumber: string, 
    fingerprint: string,
    fingerprint256: string,
    publicKey: any, 
    privateKey: string,
    signedBy: string;
    issuer: CertificateSubject,
    subject: CertificateSubject,
    notBefore: Date,
    notAfter: Date,
    havePrivateKey: boolean,
};

type PrivateKeyRow = {
    name: string;
    type: CertTypes,
    n: jsbn.BigInteger,
    e: jsbn.BigInteger,
    pairSerial: string,
    encrypted: boolean,
};

type CertificateBrief = {
    id: number,
    certType: string,
    name: string,
    issuer: CertificateSubject,
    subject: CertificateSubject,
    validFrom: Date,
    validTo: Date,
    signer: string,
    keyPresent: string,
    serialNumber: string,
    fingerprint: string,
    fingerprint256: string,
}

type KeyBrief = {
    id: number,
    name: string,
    certPair: string,
    encrypted: boolean,
}

// type OperationResult = {
//     name: string,
//     types: CertTypes[],
// }

// type OperationResultItems = {
//     added?: number[],
//     updated?: number[],
//     deleted?: number[],
// }
// type OperationResultEx = {
//     name: string,
//     types: CertTypes[],
//     roots: OperationResultItems,
//     intermediates: OperationResultItems,
//     leaves: OperationResultItems,
//     keys: OperationResultItems,
// }

type OperationResultItem = {
    type: CertTypes,
    id: number
}

type OperationResultEx2 = {
    name: string,
    types: CertTypes[],
    added: OperationResultItem[],
    updated: OperationResultItem[],
    deleted: OperationResultItem[],
}

class CertError extends Error {
    public status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }
}

const logger = log4js.getLogger();
logger.level = "debug";

export class WebServer {
    static instance: WebServer = null;
    static createWebServer(config: any): WebServer {
        if (!WebServer.instance) {
            WebServer.instance = new WebServer(config);
        }

        return WebServer.instance;
    }
    static getWebServer(): WebServer {
        return WebServer.instance;
    }
    private readonly DB_NAME = 'certs.db';
    private _port: number;
    private _dataPath: string;
    private _certificatesPath: string;
    private _privatekeysPath: string;
    private _workPath: string;
    private _dbPath: string;
    private _app: Express.Application = Express();
    private _ws = new WsServer.Server({ noServer: true });
    private _db: loki;
    private _certificates: Collection<CertificateRow>;
    private _privateKeys: Collection<PrivateKeyRow>;
    private _cache: CertificateCache;
    private _certificate: string = null;
    private _key: string = null;
    private _config: Config;
    private _version = 'v' + require('../../package.json').version;
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    private constructor(config: Config) {
        this._config = config;
        this._port = config.certServer.port;
        this._dataPath = config.certServer.root;

        if (config.certServer.certificate || config.certServer.key) {
            if (!config.certServer.certificate || !config.certServer.key) {
                throw new Error('Certificate and key must both be present of neither be present');
            }

            this._certificate = fs.readFileSync(config.certServer.certificate, { encoding: 'utf8'});
            this._key = fs.readFileSync(config.certServer.key, { encoding: 'utf8' });
        }

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
        this._app.set('views', path.join(__dirname, '../../web/views'));
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
            logger.fatal('Failed to initialize the database: ' + err.message);
            process.exit(4);
        }
        // this._app.use(Express.bodyParser.json());
        this._app.use(Express.urlencoded({ extended: true }));
        this._app.use(serveFavicon(path.join(__dirname, "../../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
        this._app.use(Express.text({ type: 'text/plain' }));
        this._app.use(Express.text({ type: 'application/x-www-form-urlencoded' }));
        this._app.use(Express.text({ type: 'application/json' }))
        this._app.use('/scripts', Express.static(path.join(__dirname, '../../web/scripts')));
        this._app.use('/styles', Express.static(path.join(__dirname, '../../web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, '../../web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, '../../web/files')));
        this._app.use('/images', Express.static(path.join(__dirname, '../../web/images')));
        this._app.use('/certificates', Express.static(this._certificatesPath));
        this._app.use('/keys', Express.static(this._privatekeysPath));
        this._app.use(FileUpload());
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
        this._app.post('/createCACert', async (request, _response, next) => {
            request.url = '/api/createcacert'
            next();
        });
        this._app.post('/createIntermediateCert', async (request, _response, next) => {
            request.url = '/api/createIntermediateCert';
            next();
        });
        this._app.post('/createLeafCert', async (request, _response, next) => {
            request.url = '/api/createLeafCert';
            next();
        });
        this._app.post('/uploadCert', ((req: any, res) => {
            // FUTURE Allow multiple files to be submitted
            // FUTURE: Allow chain style files to be submitted
            // FUTURE: Allow der and pfx files to be submitted
            if (!req.files || Object.keys(req.files).length == 0) {
                return res.status(400).send('No file selected');
            }
            let certfile = req.files.certFile;
            let tempName = path.join(this._workPath, certfile.name);
            certfile.mv(tempName, async (err: Error) => {
                if (err)
                    return res.status(500).send(err);

                try {
                    let result: OperationResultEx2  = await this._tryAddCertificate(tempName);
                    this._broadcast(result);
                    return res.status(200).json({ message: `Certificate ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
                }
                catch (err) {
                    return res.status(err.status?? 500).send(err.message);
                }
            });
        }));
        this._app.delete('/deleteCert', ((request: any, _response: any, next: NextFunction) => {
            request.url = '/api/deleteCert';
            next();
        }));
        this._app.get('/certlist', (request, response) => {
            let type: CertTypes = CertTypes[(request.query.type as any)] as unknown as CertTypes;

            if (type == undefined) {
                response.status(404).send(`Directory ${request.query.type} not found`);
            }
            else {
                let retVal: any = {};
                if (type != CertTypes.key) {
                    retVal['files'] = this._certificates.chain().find({ type: type }).simplesort('name').data().map((entry) => { 
                        return { name: entry.name, id: 'id_' + type.toString() + '_' + entry.$loki.toString() }; 
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
        this._app.get('/certdetails', async (request, response) => {
            let query = {};
            if (request.query.name) query = { name: request.query.name as string };
            else if (request.query.id) query = { $loki: parseInt(request.query.id as string) };
            else return response.status(400).json({ Message: 'Invalid URL query' });

            let c = this._certificates.findOne(query);
            if (c) {
                let retVal: CertificateBrief = this._getCertificateBrief(c);
                response.status(200).json(retVal);
            }
            else {
                response.status(404).json({ Message: 'Certificate not found' });
            }
        });
        this._app.post('/uploadKey', ((request: any, res) => {
            if (!request.files || Object.keys(request.files).length == 0) {
                return res.status(400).send('No file selected');
            }
            let keyFile = request.files.keyFile;

            if (!keyFile) {
                throw new CertError(404, 'Key file not found in request');
            }

            let tempName = path.join(this._workPath, keyFile.name);
            keyFile.mv(tempName, async (err: Error) => {
                if (err) return res.status(500).send(err);

                try {
                    let result = await this._tryAddKey(tempName, request.query.password);
                    this._broadcast(result);
                    return res.status(200).json({ message: `Key ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';')});
                }
                catch (err) {
                    return res.status(err.status ?? 500).send(err.message);
                }
            });
        }));
        this._app.delete('/deleteKey', ((request, _response, next: NextFunction) => {
            request.url = '/api/deleteKey';
            next();
        }))
        this._app.get('/keylist', (request, _response, next) => {
            request.url = '/certlist';
            next();
        });
        this._app.get('/keydetails', async (request, response) => {
            let query = {};
            if (request.query.name) query = { name: request.query.name as string };
            else if (request.query.id) query = { $loki: parseInt(request.query.id as string) };
            else return response.status(400).json({ Message: 'Invalid URL query' });

            let k = this._privateKeys.findOne(query);
            if (k) {
                let retVal: KeyBrief = this._getKeyBrief(k);
                response.status(200).json(retVal);
            }
            else {
                response.status(404).json({ Message: 'Key not found' });
            }
        });
        this._app.post('/api/createcacert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.caValidFrom? new Date(body.caValidFrom) : new Date();
                let validTo: Date = body.caValidTo? new Date(body.caValidTo) : null;
                let subject: CertificateSubject = {
                    C: body.caCountry,
                    ST: body.caState,
                    L: body.caLocation,
                    O: body.caOrganization,
                    OU: body.caUnit,
                    CN: body.caCommonName
                };
                let errString = '';

                if (!subject.CN) errString += 'Common name is required</br>\n';
                if (!validTo) errString += 'Valid to is required\n';
                if (errString) {
                    return response.status(400).json({ message: errString })
                }

                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._getAttributes(subject);
                const extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: true }),
                    new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                ]
                // Create an empty Certificate
                let cert = pki.createCertificate();
        
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
                cert.sign(privateKey, md.sha512.create());
        
                // Convert to PEM format
                await writeFile(path.join(this._workPath, 'newca.pem'), pki.certificateToPem(cert), {encoding: 'utf8'});
                await writeFile(path.join(this._workPath, 'newca-key.pem'), pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                let certResult = await this._tryAddCertificate((path.join(this._workPath, 'newca.pem')));
                let keyResult = await this._tryAddKey((path.join(this._workPath, 'newca-key.pem')));
                certResult.added = certResult.added.concat(keyResult.added);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                return response.status(200)
                    .json({ message: `Certificate/Key ${certResult.name} added`, types: [ CertTypes[CertTypes.root], CertTypes[CertTypes.key] ].join(';') });
            }
            catch (err) {
                return response.status(500).json({ error: err })
            }
        });
        this._app.post('/api/createIntermediateCert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.intValidFrom? new Date(body.intValidFrom) : new Date();
                let validTo: Date = body.intValidTo? new Date(body.intValidTo) : null;
                let subject: CertificateSubject = {
                    C: body.intCountry,
                    ST: body.intState,
                    L: body.intLocation,
                    O: body.intOrganization,
                    OU: body.intUnit,
                    CN: body.intCommonName
                };
                let errString = '';

                if (!subject.CN) errString += 'Common name is required</br>\n';
                if (!validTo) errString += 'Valid to is required\n';
                if (!body.intSigner) errString += 'Signing certificate is required';
                if (errString) {
                    return response.status(400).json({ message: errString })
                }

                const cRow = this._certificates.findOne({name: body.intSigner});
                const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });

                if (!cRow) {
                    return response.status(404).json({ message: 'Could not find signing certificate'});
                }
                if (!kRow) {
                    return response.status(404).json({ message: 'Could not find signing certificate\'s private key'});
                }

                const c = pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, cRow.name + '.pem'), { encoding: 'utf8' }));
                let k: pki.PrivateKey;

                if (c) {
                    if (body.intPassword) {
                        k = pki.decryptRsaPrivateKey(await readFile(path.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }), body.intPassword);
                    }
                    else {
                        k = pki.privateKeyFromPem(await readFile(path.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }));
                    }
                }
                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._getAttributes(subject);
                const extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: true }),
                    new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                ]
                // Create an empty Certificate
                let cert = pki.createCertificate();
        
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
                cert.sign(k, md.sha512.create());
        
                // Convert to PEM format
                await writeFile(path.join(this._workPath, 'newint.pem'), pki.certificateToPem(cert), {encoding: 'utf8'});
                await writeFile(path.join(this._workPath, 'newint-key.pem'), pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                let certResult = await this._tryAddCertificate((path.join(this._workPath, 'newint.pem')));
                let keyResult = await this._tryAddKey((path.join(this._workPath, 'newint-key.pem')));
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
        });
        this._app.post('/api/createLeafCert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.leafValidFrom? new Date(body.leafValidFrom) : new Date();
                let validTo: Date = body.leafValidTo? new Date(body.leafValidTo) : null;
                let subject: CertificateSubject = {
                    C: body.leafCountry,
                    ST: body.leafState,
                    L: body.leafLocation,
                    O: body.leafOrganization,
                    OU: body.leafUnit,
                    CN: body.leafCommonName
                };
                let errString = '';

                if (!subject.CN) errString += 'Common name is required</br>\n';
                if (!validTo) errString += 'Valid to is required\n';
                if (errString) {
                    return response.status(400).json({ message: errString })
                }

                const cRow = this._certificates.findOne({name: body.leafSigner});
                const kRow = this._privateKeys.findOne({ pairSerial: cRow.serialNumber });

                if (!cRow || !kRow) {
                    return response.status(500).json({ message: 'Unexpected database corruption - rows missing'});
                }

                const c = pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, cRow.name + '.pem'), { encoding: 'utf8' }));
                let k: pki.PrivateKey;

                if (c) {
                    if (body.leafPassword) {
                        k = pki.decryptRsaPrivateKey(fs.readFileSync(path.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }), body.leafPassword);
                    }
                    else {
                        k = pki.privateKeyFromPem(fs.readFileSync(path.join(this._privatekeysPath, kRow.name + '.pem'), { encoding: 'utf8' }));
                    }
                }
                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._getAttributes(subject);
                let sal:ExtensionSubjectAltNameOptions = { domains: [ subject.CN ] };
                let extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: false }),
                    new ExtensionSubjectKeyIdentifier({}),
                    new ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
                    new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                    new ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true }),
                    new ExtensionSubjectAltName(sal),
                ];
                // Create an empty Certificate
                let cert = pki.createCertificate();
        
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
                cert.sign(k, md.sha512.create());

                // Convert to PEM format
                await writeFile(path.join(this._workPath, 'newleaf.pem'), pki.certificateToPem(cert), {encoding: 'utf8'});
                await writeFile(path.join(this._workPath, 'newleaf-key.pem'), pki.privateKeyToPem(privateKey), { encoding: 'utf8' });
                let certResult = await this._tryAddCertificate((path.join(this._workPath, 'newleaf.pem')));
                let keyResult = await this._tryAddKey((path.join(this._workPath, 'newleaf-key.pem')));
                certResult.added = certResult.added.concat(keyResult.added);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                let retTypes = Array.from(new Set(certResult.types.concat(keyResult.types).concat([CertTypes.leaf]))).map((type) => CertTypes[type]);
                return response.status(200)
                    .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added`, types: retTypes.join(';') });
            }
            catch (err) {
                return response.status(500).json({ message: err.message })
            }
        });
        this._app.get('/api/certname', async(request, response) => {
            let c = this._certificates.findOne({ $loki: parseInt(request.query.id as string)});
            if (c) {
                response.status(200).json({ 'name': c.name });
            }
            else {
                response.status(404).json({ Message: 'Certificate not found' });
            }
        });
        this._app.post('/api/uploadCert', async (request, response) => {
            if (!(request.body as string).includes('\n')) {
                return response.status(400).send('Certificate must be in standard 64 byte line length format - try --data-binary on curl');
            }
            try {
                await writeFile(path.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                //writeFileSync(path.join(this._workPath, 'upload.pem'), request.body, { encoding: 'utf8' });
                let result: OperationResultEx2 = await this._tryAddCertificate(path.join(this._workPath, 'upload.pem'));
                this._broadcast(result);
                return response.status(200).json({ message: `Certificate ${result.name} added`, types: result.types.map((t) => CertTypes[t]).join(';') });
            }
            catch (err) {
                response.status(500).send(err.message);
            }
        });
        this._app.delete('/api/deleteCert', async (request, response) => {
            try {
                let options: { serialNumber?: string, name?: string } = {};
                if (request.query.serialNumber) options['serialNumber'] = request.query.serialNumber as string;
                else options['name'] = request.query.name as string;
                let result: OperationResultEx2 = await this._tryDeleteCert(options);
                this._broadcast(result);
                return response.status(200).json({ message: `Certificate ${result.name} deleted` , types: result.types.map((t) => CertTypes[t]).join(';') });
            }
            catch (err) {
                return response.status(err.status?? 500).json(JSON.stringify({ error: err.message }));
            }
        });
        this._app.get('/api/keyname', async(request, response) => {
            let c = this._privateKeys.findOne({ $loki: parseInt(request.query.id as string)});
            if (c) {
                response.status(200).json({ 'name': c.name });
            }
            else {
                response.status(404).json({ Message: 'Key not found' });
            }
        });
        this._app.post('/api/uploadKey', async (request, response) => {
            try {
                if (typeof request.body != 'string') {
                    return response.status(400).send('Content type must be text/plain');
                }
                if (!(request.body as string).includes('\n')) {
                    return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary on curl');
                }
                await writeFile(path.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                // writeFileSync(path.join(this._workPath, 'upload.key'), request.body, { encoding: 'utf8' });
                let result: OperationResultEx2 = await this._tryAddKey(path.join(this._workPath, 'upload.key'), request.query.password as string);
                this._broadcast(result);
                return response.status(200).json({ message: `Key ${result.name} added`, type: result.types.map((t) => CertTypes[t]).join(';')});
            }
            catch (err) {
                response.status(500).send(err.message);
            }
        });
        this._app.delete('/api/deleteKey', async (request, response) => {
            try {
                let options: { name: string } = { name: null };
                options.name = request.query.name as string;
                let result: OperationResultEx2 = await this._tryDeleteKey(options);
                this._broadcast(result);
                return response.status(200).json({ message: `Key ${result.name} deleted` , types: result.types.map((t) => CertTypes[t]).join(';') });
            }
            catch (err) {
                return response.status(err.status?? 500).json({ error: err.message });
            }
        });
        this._app.get('/api/chaindownload', async (request, response) => {
            try {
                if (!await exists(path.join(this._certificatesPath, request.query.name + '.pem'))) {
                    throw new CertError(404, `${request.query.name} not found`);
                }
                let filename = await this._getChain(request.query.name as string);
                response.download(filename, request.query.name + '_full_chain.pem', async (err) => {
                    if (err) {
                        logger.error(`Failed to send chain for ${request.query.name}: ${err.message}`);
                    }
                    await unlink(filename);
                });
            }
            catch (err) {
                return response.status(err.status?? 500).json({ error: err.message });
            }
        });

        let server: http.Server | https.Server;

        if (this._certificate) {
            const options = {
                cert: this._certificate,
                key: this._key,
            };
            server = https.createServer(options, this._app).listen(this._port, '0.0.0.0');
        }
        else {
            server = http.createServer(this._app).listen(this._port, '0.0.0.0');
        }
        logger.info('Listening on ' + this._port);

        server.on('upgrade', async (request, socket, head) => {
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
        });
    }

    private async _dbInit(): Promise<void> {
        return new Promise<void>(async (resolve, reject) => {
            try {
                let files: string[];
                let certRows: CertificateRow[] = this._certificates.chain().simplesort('name').data();

                certRows.forEach((row: CertificateRow) => {
                    if (!fs.existsSync(path.join(this._certificatesPath, row.name + '.pem'))) {
                        logger.warn(`Certificate ${row.name} not found - removed`);
                        this._certificates.remove(row);
                        this._certificates.chain().find({'serialNumber': row.signedBy }).update((r) => {
                            r.serialNumber = null;
                            logger.warn(`Removed signedBy from ${r.name}`);
                        });
                        this._privateKeys.chain().find({ pairSerial: row.serialNumber }).update((k) => {
                            k.pairSerial = null;
                            logger.warn(`Removed relationship to private key from ${k.name}`);
                        });
                    }
                });

                files = fs.readdirSync(this._certificatesPath);

                let adding: Promise<OperationResultEx2>[] = [];

                files.forEach(async (file) => {
                    let cert = this._certificates.findOne({ name: path.parse(file).name });
                    if (!cert) {
                        try {
                            adding.push(this._tryAddCertificate(path.join(this._certificatesPath, file)));
                        }
                        catch (err) {}
                    }
                });

                await Promise.all(adding);
                // let addresults: string[] = await Promise.all(adding);
                // logger.debug(addresults.join(';'));

                let nonRoot = this._certificates.find( { '$and': [ { 'type': { '$ne': CertTypes.root }}, { signedBy: null } ] });

                for (let i: number = 0; i < nonRoot.length; i++) {
                    let signer = await this._findSigner(pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, nonRoot[i].name + '.pem'), { encoding: 'utf8' })));
                    if (signer != null) {
                        logger.info(`${nonRoot[i].name} is signed by ${signer.name}`);
                        nonRoot[i].signedBy = signer.serialNumber;
                        this._certificates.update(nonRoot[i]);
                    }
                }

                let keyRows: PrivateKeyRow[] = this._privateKeys.chain().simplesort('name').data();

                keyRows.forEach((key) => {
                    if (!existsSync(path.join(this._privatekeysPath, key.name + '.pem'))) {
                        logger.warn(`Key ${key.name} not found - removed`);
                        this._privateKeys.remove(key);
                    }
                });

                files = fs.readdirSync(this._privatekeysPath);

                adding = [];
                files.forEach(async (file) => {
                    // logger.debug(path.basename(file));
                    let key = this._privateKeys.findOne({ name: path.parse(file).name });
                    if (!key) {
                        try {
                            adding.push(this._tryAddKey(path.join(this._privatekeysPath, file)));
                        }
                        catch (err) {
                            logger.debug('WTF');
                        }
                    }
                });

                // addresults = await Promise.all(adding);
                await Promise.allSettled(adding);
                // logger.debug(addresults.join(';'));

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

    private async _tryAddCertificate(filename: string): Promise<OperationResultEx2> {
        return new Promise<OperationResultEx2>(async (resolve, reject) => {
            logger.info(`Trying to add ${path.basename(filename)}`);
            if (!fs.existsSync(filename)) {
                let err = new CertError(404, `${path.basename(filename)} does not exist`)
                throw err;
            }

            try {
                let pemString = await readFile(filename, { encoding: 'utf8' });
                let msg = pem.decode(pemString)[0];
                logger.debug(`Received ${msg.type}`);

                if (msg.type != 'CERTIFICATE') {
                    throw new CertError(400, 'Unsupported type ' + msg.type);
                }

                let result: OperationResultEx2 = { name: '', types: [], added: [], updated: [], deleted: [] };
                let c: pki.Certificate = pki.certificateFromPem(pemString);
                let signedBy: string = null;
                let havePrivateKey: boolean = false;

                // See if we already have this certificate
                if (this._certificates.findOne({ serialNumber: c.serialNumber }) != null) {
                    throw new CertError(409, `${path.basename(filename)} serial number ${c.serialNumber} is a duplicate - ignored`);
                }

                // See if this is a root, intermiate, or leaf
                if (c.isIssuer(c)) {
                    result.types.push(CertTypes.root);
                    signedBy = c.serialNumber;
                }
                else {
                    let bc: any = c.getExtension('basicConstraints');

                    if ((bc != null) && (bc.cA ?? false) == true && (bc.pathlenConstraint ?? 1) > 0) {
                        result.types.push(CertTypes.intermediate);
                    }
                    else {
                        result.types.push(CertTypes.leaf);
                    }

                    // See if any existing certificates signed this one
                    let signer = await this._findSigner(c);

                    if (signer != null) {
                        signedBy = signer.serialNumber;
                    }
                }
                
                if (result.types[0] != CertTypes.leaf) {
                    // Update certificates that this one signed
                    let signeeList = this._certificates.find({ 'type': { '$in': [ CertTypes.leaf, CertTypes.intermediate ] }});
                    let list: { types: CertTypes[], updated: OperationResultItem[] } = await this._findSigned(signeeList, c);

                    result.types = result.types.concat(list.types);
                    result.updated = result.updated.concat(list.updated);
                }

                // Generate a filename for the common name
                let name = (c.subject.getField('CN').value).replace(/ /g, '_');
                result.name = name;

                // Deduplicate if necessary
                if (name + '.pem' != path.basename(filename)) {
                    if (await exists(path.join(path.dirname(filename), name + '.pem'))) {
                        for (let i = 1; true; i++) {
                            if (await exists(path.join(path.dirname(filename), name + '_' + i.toString() + '.pem'))) {
                                name = name + '_' + i.toString();
                                break;
                            }
                        }
                    }
                    logger.info(`Renamed ${path.basename(filename)} to ${name}.pem`)
                    await rename(filename, path.join(this._certificatesPath, name + '.pem'));

                    // See if we have private key for this certificate
                    let keys: (PrivateKeyRow & LokiObj)[] = this._privateKeys.chain().find({ pairSerial: null }).data();

                    for (let i = 0; i < keys.length; i++) {
                        if (this._isSignedBy(c, keys[i].n, keys[i].e)) {
                            logger.info('Found private key for ' + name);
                            havePrivateKey = true;
                            await rename(path.join(this._privatekeysPath, keys[i].name + '.pem'), path.join(this._privatekeysPath, name + '_key.pem'));
                            keys[i].name = name + '_key';
                            keys[i].pairSerial = c.serialNumber;
                            this._privateKeys.update(keys[i]);
                            result.types.push(CertTypes.key);
                            result.updated.push({ type: CertTypes.key, id: keys[i].$loki });
                            break;
                        }
                    }
                }

                logger.info(`Certificate ${name} added`);
                // This is declared as returning the wrong type hence any
                let newRecord: CertificateRow | LokiObj = this._certificates.insert({ 
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
                    fingerprint: new crypto.X509Certificate(pemString).fingerprint,
                    fingerprint256: new crypto.X509Certificate(pemString).fingerprint256,
                });

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
                result.added.push({ type: result.types[0], id: (newRecord as unknown as LokiObj).$loki });
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
        });
    }

    private _getCertificateBrief(r: CertificateRow & LokiObj): CertificateBrief {
        let signer = null;
        if (r.signedBy != null) {
            let s = this._certificates.findOne({ serialNumber: r.signedBy });
            if (s != null) signer = s.name;
            else logger.warn(`Signed by certificate missing for ${r.name}`);
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
            serialNumber: r.serialNumber == null? '' : r.serialNumber.match(/.{1,2}/g).join(':'),  // Hacky fix for dude entries in db
            signer: signer,
            keyPresent: key != null? 'yes' : 'no',
            fingerprint: r.fingerprint,
            fingerprint256: r.fingerprint256,
         };
    }

    private async _tryDeleteCert(options: { serialNumber?: string, name?: string }): Promise<OperationResultEx2> {
        return new Promise<OperationResultEx2>(async (resolve, reject) => {
            // TODO: Add try block
            let cert: CertificateRow & LokiObj = this._certificates.findOne(options.serialNumber? { serialNumber: options.serialNumber } : { name: options.name });

            if (!cert) {
                reject(new CertError(404, `Unable to find certificate with ${options.serialNumber? 'serial number' : 'name'} ${options.serialNumber ?? options.name}`));
            }
            let filename = path.join(this._certificatesPath, cert.name + '.pem');

            if (await exists(filename)) {
                await unlink(filename);
            }
            let result: OperationResultEx2 = {
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
                let unknownName = await this._getUnpairedKeyName();
                await rename(path.join(this._privatekeysPath, key.name + '.pem'), path.join(this._privatekeysPath, unknownName + '.pem'));
                key.name = unknownName;
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
            })

            // let signed = this._certificates.find({ signedBy: cert.serialNumber });

            // for (let i = 0; i < signed.length; i++) {
            //     result.types.push(signed[i].type);
            //     result.updated.push({ type: signed[i].type, id: signed[i].$loki });
            //     signed[i]
            // }

            this._certificates.remove(cert);

            resolve(result);
        });
    }

    private async _tryAddKey(filename: string, password?: string): Promise<OperationResultEx2> {
        return new Promise<OperationResultEx2>(async (resolve, reject) => {
            logger.info(`Trying to add ${path.basename(filename)}`);
            if (!await exists(filename)) {
                reject(new CertError(404, `${path.basename(filename)} does not exist`));
            }

            try {
                let result: OperationResultEx2 = {
                    name: '',
                    types: [],
                    added: [],
                    updated: [],
                    deleted: [],
                };

                let k: pki.rsa.PrivateKey;
                let kpem = await readFile(filename, { encoding: 'utf8' });
                let msg = pem.decode(kpem)[0];
                let encrypted: boolean = false;
                if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                    if (!password) {
                        logger.warn(`Cannot add ${filename} - no pasword for encrypted key`); 
                        return reject(new CertError(400, 'Password is required for key ' + filename));
                    }
                    k = pki.decryptRsaPrivateKey(kpem , password);
                    encrypted = true;
                }
                else {
                    k = pki.privateKeyFromPem(kpem);
                }

                let krow: PrivateKeyRow = { e: k.e, n: k.n, pairSerial: null, name: null, type: CertTypes.key, encrypted: encrypted };
                let keys = this._privateKeys.find();
                let publicKey = pki.setRsaPublicKey(k.n, k.e);

                // See if we already have this key
                for (let i = 0; i < keys.length; i++) {
                    if (this._isIdenticalKey(pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                        reject(new CertError(409, `Key already present: ${keys[i].name}`));
                    }
                }
                
                // See if this is the key pair for a certificate
                let certs = this._certificates.find();
                let newfile = 'unknown_key_';
                // let types: CertTypes[] = [CertTypes.key];

                for (let i = 0; i < certs.length; i++) {
                    if (this._isSignedBy(await this._cache.getCertificate(certs[i].name), k.n, k.e)) {
                        krow.pairSerial = certs[i].serialNumber;
                        result.types.push(certs[i].type);
                        result.updated.push({ type: certs[i].type, id: certs[i].$loki });
                        newfile = certs[i].name + '_key';
                        break;
                    }
                }

                // Generate a file name for a key without a certificate
                if (krow.pairSerial == null) {
                    newfile = await this._getUnpairedKeyName();
                }

                result.name = newfile;
                await rename(filename, path.join(this._privatekeysPath, newfile + '.pem'));
                logger.info(`Renamed ${path.basename(filename)} to ${newfile}.pem`)
                krow.name = newfile;
                let newRecord: PrivateKeyRow | LokiObj = this._privateKeys.insert(krow);
                result.added.push({ type: CertTypes.key, id: (newRecord as unknown as LokiObj).$loki });

                resolve(result);
            }
            catch (err) {
                logger.error(err.message);
                if (!err.status) {
                    err.status = 500;
                }
                reject(err);
            }
        });
    }

    private _getKeyBrief(r: PrivateKeyRow & LokiObj): KeyBrief {
        return {
            id: r.$loki,
            name: r.name,
            certPair: (r.pairSerial == null)? 'Not present' : r.name.substring(0, r.name.length -4),
            encrypted: r.encrypted,
        }
    }

    private _tryDeleteKey(options: { name: string }): Promise<OperationResultEx2> {
        return new Promise<OperationResultEx2>(async (resolve, reject) => {
            let result: OperationResultEx2 = { types: [CertTypes.key], name: '', added: [], updated: [], deleted: [] };
            let key: PrivateKeyRow & LokiObj = this._privateKeys.findOne({ name: options.name });

            if (!key) {
                reject(new CertError(404, `Unable to find key with name ${options.name}`));
            }

            let filename = path.join(this._privatekeysPath, key.name + '.pem');

            if (await exists(filename)) {
                await unlink(filename);
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
                    result.updated.push({type: cert.type, id: cert.$loki })
                    // certificatesupdated.push(cert.$loki);
                }
            }

            result.deleted.push({ type: CertTypes.key, id: key.$loki });
            this._privateKeys.remove(key);

            resolve(result);
        });
    }

    private async _getChain(certName: string): Promise<string> {
        return new Promise(async (resolve, reject) => {
            try {
                let newFile = path.join(this._workPath, 'temp_');
                let i = 0;
                while (await exists(newFile + i.toString())) {
                    i++;
                }

                newFile += i.toString();
                await copyFile(path.join(this._certificatesPath, certName + '.pem'), newFile);

                let c: CertificateRow = this._certificates.findOne({ name: certName });

                while (c.serialNumber != c.signedBy) {
                    c = this._certificates.findOne({ serialNumber: c.signedBy});
                    await appendFile(newFile, await readFile(path.join(this._certificatesPath, c.name + '.pem')));
                }

                resolve(newFile);
            }
            catch (err) {
                reject(new CertError(500, err.message));
            }
        });
    }

    private static _getSubject(s: pki.Certificate['issuer'] | pki.Certificate['subject']): CertificateSubject {
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

    private async _getUnpairedKeyName(): Promise<string> {
        return new Promise(async (resolve, _reject) => {
            let newname = 'unknown_key_';
            for (let i = 0; true; i++) {
                if (!await exists(path.join(this._privatekeysPath, newname + i.toString() + '.pem'))) {
                    resolve(newname + i.toString());
                }
            }
        });
    }

    private async _findSigner(certificate: pki.Certificate): Promise<CertificateRow & LokiObj> {
        return new Promise<CertificateRow & LokiObj>(async(resolve, _reject) => {
            let caList = this._certificates.find({ 'type': { '$in': [ CertTypes.root, CertTypes.intermediate ] }});
            for (let i = 0; i < caList.length; i++) {
                try {
                    // TODO: Deprecate cache
                    let c = await this._cache.getCertificate(caList[i].name);
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
        });
    }

    private async _findSigned(signeeList: (CertificateRow & LokiObj)[], certificate: pki.Certificate): Promise<{ types: CertTypes[], updated: OperationResultItem[] }> {
        return new Promise<{ types: CertTypes[], updated: OperationResultItem[] }>(async (resolve, reject) => {
            let retVal: { types: CertTypes[], updated: OperationResultItem[] } = { types: [], updated: [] };
            try {
                signeeList.forEach(async (s) => {
                    // TODO: Deprecate cache
                    let check = await this._cache.getCertificate(s.name);
                    try {
                        if (certificate.verify(check)) {
                            this._certificates.chain().find({ 'serialNumber': check.serialNumber }).update((u) => {
                                u.signedBy = certificate.serialNumber;
                            });
                            logger.debug(`Marked ${s.name} as signed by ${certificate.subject.getField('CN')}`);
                            retVal.types.push(s.type);
                            retVal.updated.push({ type: s.type, id: s.$loki });
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

    private _broadcast(data: OperationResultEx2): void {
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

    private static _sanitizeName(name: string): string {
        return name.replace(/[\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }
 
    private static _getAttributes(subject: CertificateSubject): pki.CertificateField[] {
        let attributes: pki.CertificateField[] = [];
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
    private static  _getRandomSerialNumber(): string {
        return WebServer._makeNumberPositive(util.bytesToHex(random.getBytesSync(20)));
    }

    private static _makeNumberPositive = (hexString: string): string => {
        let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);

        if (mostSignificativeHexDigitAsInt < 8)
            return hexString;

        mostSignificativeHexDigitAsInt -= 8;
        return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
    };
}

