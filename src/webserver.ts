import { existsSync, mkdirSync } from 'node:fs';
import path from 'path';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { readFile } from 'fs/promises'

import { /* pki, */ pem, /* util, random, md */ } from 'node-forge'; 
import loki, { Collection, LokiFsAdapter } from 'lokijs'
import Express, { NextFunction, /* response */ } from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';
import WsServer from 'ws';
import { Readable } from 'stream';
import * as log4js from 'log4js';

import { EventWaiter } from './utility/eventWaiter';
import { exists } from './utility/exists';
// import { ExtensionParent } from './extensions/ExtensionParent';
// import { ExtensionBasicConstraints } from './extensions/ExtensionBasicConstraints';
// import { ExtensionKeyUsage } from './extensions/ExtensionKeyUsage';
// import { ExtensionAuthorityKeyIdentifier } from './extensions/ExtensionAuthorityKeyIdentifier';
// import { ExtensionSubjectKeyIdentifier } from './extensions/ExtensionSubjectKeyIdentifier';
// import { ExtensionExtKeyUsage } from './extensions/ExtensionExtKeyUsage';
// import { ExtensionSubjectAltName, ExtensionSubjectAltNameOptions } from './extensions/ExtensionSubjectAltName';
import { OperationResult, ResultType } from './webservertypes/OperationResult';
import { CertTypes } from './webservertypes/CertTypes';
import { Config } from './webservertypes/Config';
// import { CertificateSubject } from './webservertypes/CertificateSubject';
import { CertificateRow } from './webservertypes/CertificateRow';
import { PrivateKeyRow } from './webservertypes/PrivateKeyRow';
import { DBVersionRow } from './webservertypes/DBVersionRow';
import { CertificateLine } from './webservertypes/CertificateLine';
import { CertificateBrief } from './webservertypes/CertificateBrief';
import { KeyBrief } from './webservertypes/KeyBrief';
// import { GenerateCertRequest } from './webservertypes/GenerateCertRequest';
import { QueryType } from './webservertypes/QueryType';
import { userAgentOS } from './webservertypes/userAgentOS';
import { CertError } from './webservertypes/CertError';
import { CertMultiError } from "./webservertypes/CertMultiError";
import { KeyLine } from './webservertypes/KeyLine';
// import { CertificateInput } from './webservertypes/CertificateInput';
import { KeyStores } from './database/keyStores';
import { KeyUtil } from './database/keyUtil';
import { CertificateStores } from './database/certificateStores';
import { CertificateUtil } from './database/certificateUtil';
import { OperationResultItem } from './webservertypes/OperationResultItem';
import { DbStores } from './database/dbStores';

const logger = log4js.getLogger();
logger.level = "debug";

/**
 * @classdesc Web server to help maintain test certificates and keys in the file system and a database.
 */
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
    private _dbPath: string;
    private _app: Express.Application = Express();
    private _ws = new WsServer.Server({ noServer: true });
    private _db: loki;
    private _certificate: string = null;
    private _key: string = null;
    private _config: Config;
    private _version = 'v' + require('../../package.json').version;
    private static readonly _lowestDBVersion: number = 0;
    private _currentVersion: number = 4;
    get port() { return this._port; }
    get dataPath() { return this._dataPath; }
    /**
     * @constructor
     * @param config Configuration information such as port, etc.
     */
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

        if (config.certServer.subject.C && config.certServer.subject.C.length != 2) {
            throw new Error(`Invalid country code ${config.certServer.subject.C} - must be two characters`);
        }

        this._certificatesPath = path.join(this._dataPath, 'certificates');
        this._privatekeysPath = path.join(this._dataPath, 'privatekeys');
        this._dbPath = path.join(this._dataPath, 'db');

        if (!existsSync(this._dataPath))
            mkdirSync(this._dataPath, { recursive: true });
        if (!existsSync(this._certificatesPath)) 
            mkdirSync(this._certificatesPath);
        if (!existsSync(this._privatekeysPath)) 
            mkdirSync(this._privatekeysPath);
        if (!existsSync(this._dbPath)) 
            mkdirSync(this._dbPath);

        this._app.set('views', path.join(__dirname, '../../web/views'));
        this._app.set('view engine', 'pug');
    }

    /**
     * Starts the webserver and defines the express routes.
     * 
     * @returns Promise\<void>
     */
    async start() {
        type cshostType = {
            protocol: string,
            hostname: string,
            port: number,
        }
        const csHost: (c: cshostType) => string = ({ protocol, hostname, port }) => `${protocol}://${hostname}:${port}`;
        logger.info(`CertServer starting - ${this._version}`);
        let getCollections: () => void = () => {
            if (null == (certificates = db.getCollection<CertificateRow>('certificates'))) {
                certificates = db.addCollection<CertificateRow>('certificates', { });
            }
            if (null == (privateKeys = db.getCollection<PrivateKeyRow>('privateKeys'))) {
                privateKeys = db.addCollection<PrivateKeyRow>('privateKeys', { });
            }
            if (null == (dbVersion = db.getCollection<DBVersionRow>('dbversion'))) {
                dbVersion = db.addCollection<DBVersionRow>('dbversion', { });
            }

            ew.EventSet();
        }

        try {
            var ew = new EventWaiter();
            var certificates: Collection<CertificateRow> = null;
            var privateKeys: Collection<PrivateKeyRow> = null;
            var dbVersion: Collection<DBVersionRow> = null;
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

            CertificateStores.Init(certificates, path.join(this._dataPath, 'certificates'));
            KeyStores.Init(privateKeys, path.join(this._dataPath, 'privatekeys'));
            DbStores.Init(dbVersion);

            await this._dbInit();
        }
        catch (err) {
            logger.fatal('Failed to initialize the database: ' + err.message);
            process.exit(4);
        }

        this._app.use(Express.urlencoded({ extended: true }));
        this._app.use(serveFavicon(path.join(__dirname, "../../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
        this._app.use(Express.json({ type: '*/json' }));
        this._app.use(Express.text({ type: 'text/plain' }));
        this._app.use(Express.text({ type: 'application/x-www-form-urlencoded' }));
        this._app.use(Express.text({ type: 'application/json' }));
        this._app.use('/scripts', Express.static(path.join(__dirname, '../../web/scripts')));
        this._app.use('/styles', Express.static(path.join(__dirname, '../../web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, '../../web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, '../../web/files')));
        this._app.use('/images', Express.static(path.join(__dirname, '../../web/images')));
        this._app.use(FileUpload());
        this._app.use((request, response, next: NextFunction) => {
            const redirects: { [key: string]: string } = {
                '/api/uploadCert':          '/api/uploadPem',
                '/api/helpers':             '/api/helper',
                '/api/script':              '/api/helper',
                '/createCACert':              '/api/createCACert',
                '/createIntermediateCert':  '/api/createIntermediateCert',
                '/createLeafCert':          '/api/createLeafCert',
                '/deleteCert':              '/api/deleteCert',
                '/certList':                '/api/certList',
                '/certDetails':             '/api/certDetails',
                '/deleteKey':               '/api/deleteKey',
                '/keyList':                 '/certList',
                '/keyDetails':              '/api/keyDetails',
                '//api/getCertPem':         '/api/getCertificatePem',
                '/api/uploadKey':           '/api/uploadPem',
            };
            try {
                if (request.path in redirects) {
                    logger.debug(`Redirecting ${request.path} to ${redirects[request.path]}`)
                    request.url = redirects[request.path];
                }
                logger.debug(`${request.method} ${request.url}`);
                next();
            }
            catch (err) {
                response.status(err.status ?? 500).json({ error: err.message });
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
        this._app.get('/api/helper', async (request, response) => {
            try {
                response.setHeader('content-type', 'application/text');
                let userAgent = request.get('User-Agent')
                let os: userAgentOS;

                if (request.query.os) {
                    if ((request.query.os as string).toUpperCase() in userAgentOS) {
                        let work: keyof typeof userAgentOS = ((request.query.os as string).toUpperCase() as 'LINUX' | 'WINDOWS' | 'MAC');
                        os = userAgentOS[work];
                        logger.debug(`OS specified as ${userAgentOS[os]}`);
                    }
                    else {
                        return response.status(400).json({ error: `OS invalid or unsupported ${request.query.os as string}` });
                    }
                }
                else {
                    os = WebServer._guessOs(userAgent);
                    logger.debug(`${userAgent} guessed to be ${userAgentOS[os]}`);
                }

                let hostname = `${csHost({ protocol: this._certificate ? 'https' : 'http', hostname: request.hostname, port: this._port })}`;
                let readable: Readable;

                if (os == userAgentOS.LINUX || os == userAgentOS.MAC) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.sh"`);
                    readable = Readable.from([
                        `export CERTSERVER_HOST=${hostname}\n`,
                        `export REQUEST_PATH=${request.path}\n`,
                    ].concat(((await readFile('src/files/linuxhelperscript.sh', { encoding: 'utf8' })).split('\n').map((l) => l + '\n'))));
                }
                else if (os == userAgentOS.WINDOWS) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.ps1"`);
                    readable = Readable.from([
                        `Set-Item "env:CERTSERVER_HOST" -Value "${hostname}"\n`,
                        `Set-Item "env:REQUEST_PATH" -Value "${request.path}"\n`,
                    ].concat(((await readFile('src/files/windowshelperscript.ps1', { encoding: 'utf8' })).split('\n').map((l) => l + '\n'))));
                }
                else {
                    return response.status(400).json({ error: `No script for OS ${userAgentOS[os]}}` });
                }
                logger.debug('Sending file');
                readable.pipe(response);
            }
            catch (err) {
                logger.error(err);
            }
        });
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
        this._app.post('/updateCertTag', async (request, _response, next) => {
            request.url = '/api/updateCertTag';
            request.query['id'] = request.body.toTag;
            next();
        });
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
        this._app.post(/\/api\/create.*Cert/i, async (request, response) => {
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
                let type: CertTypes =
                      request.url.includes('createCACert') 
                    ? CertTypes.root 
                    : request.url.includes('createIntermediateCert')
                    ? CertTypes.intermediate
                    : CertTypes.leaf;

                let { certificatePem, keyPem, result } = await CertificateUtil.generateCertificatePair(type, request.body);

                if (result.hasErrors) {
                    return response.status(result.statusCode).json(result.getResponse());
                }
                let certResult = await this._tryAddCertificate({ pemString: certificatePem });
                let keyResult = await this._tryAddKey({ pemString: keyPem });
                certResult.merge(keyResult);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                let certId = certResult.added[0].id;
                let keyId = keyResult.added[0].id;
                return response.status(200)
                    .json({ 
                        success: true,
                        title: 'Certificate/Key Added',
                        messages: [ `Certificate/Key ${certResult.name}/${keyResult.name} added` ], 
                        newIds: { certificateId: certId, keyId: keyId } 
                    });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
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
        this._app.get('/api/certName', async(request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                return response.status(200).json({ name: c.subject.CN, id: c.$loki, tags: c.tags?? [] });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/certDetails', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let retVal: CertificateBrief = c.certificateBrief();
                response.status(200).json(retVal);
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/keyList', (request, _response, next) => {
            request.url = '/api/certList';
            request.query = { type: 'key' };
            next();
        });
        this._app.get('/api/keyDetails', async (request, response) => {
        
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                let retVal: KeyBrief = k.keyBrief;
                response.status(200).json(retVal);
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/certList', (request, response) => {
            try {
                let type: CertTypes = CertTypes[(request.query.type as any)] as unknown as CertTypes;

                if (type == undefined) {
                    throw new CertError(404, `Directory ${request.query.type} not found`);
                }
                else {
                    let retVal: CertificateLine[] | KeyLine[] = [];
                    if (type != CertTypes.key) {
                        retVal = CertificateStores.find({ type: type }).sort((l, r) => l.name.localeCompare(r.name)).map((entry): CertificateLine => { 
                            return { 
                                name: entry.subject.CN, 
                                type: CertTypes[type].toString(), 
                                id: entry.$loki, 
                                tags: entry.tags?? [], 
                                keyId: entry.keyId 
                            }; 
                        });
                    }
                    else {
                        retVal = KeyStores.find().sort((l, r) => l.name.localeCompare(r.name)).map((entry): KeyLine => { 
                            return { 
                                name: entry.name, 
                                type: CertTypes[type].toString(), 
                                id: entry.$loki 
                            };
                        });
                    }
                    return response.status(200).json({ files: retVal });
                }
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        // this._app.get('/api/getCertPem', async (request, _response, next) => {
        //     request.url = '/api/getCertificatePem';
        //     next();
        // });
        this._app.get('/api/getCertificatePem', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);

                response.download(c.absoluteFilename, c.name + '.pem', (err) => {
                    if (err) {
                        throw new CertError(500, `Failed to find file for ${request.query}: ${err.message}`);
                    }
                })
            }
            catch (err) {
                logger.error('Certificate download failed: ', err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.delete('/api/deleteCert', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let result: OperationResult = await this._tryDeleteCert(c);
                this._broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.post('/api/updateCertTag', async (request, response) => {
            try {
                let tags: { tags: string[], lastTag: string, toTag: string } =  request.body;
                if (tags.tags === undefined) tags.tags = []
                else if (!Array.isArray(tags.tags)) tags.tags = [ tags.tags ];
                let cleanedTags: string[] = tags.tags.map((t) => t.trim()).filter((t) => t != '');
                for (let tag in cleanedTags) {
                    if (tag.match(/[;<>\(\)\{\}\/]/) !== null) throw new CertError(400, 'Tags cannot contain ; < > / { } ( )');
                }
                let result: OperationResult = this._resolveCertificateUpdate(request.query as QueryType, (c) => {
                    c.updateTags(cleanedTags);
                });
                result.pushMessage('Certificate tags updated', ResultType.Success);
                this._broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/keyname', async(request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                response.status(200).json({ name: k.name, id: k.$loki, tags: [] });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        // this._app.post('/api/uploadKey', async (request, _response, next) => {
        //     request.url = '/api/uploadPem';
        //     next();
        // });
        this._app.delete('/api/deleteKey', async (request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                let result: OperationResult = await this._tryDeleteKey(k);
                this._broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/getKeyPem', async (request, response) => {

            try {
                let k: KeyUtil = this._resolveKeyQuery(request.query as QueryType);
                response.download(k.absoluteFilename, k.name + '.pem', (err) => {
                    if (err) {
                        throw new CertError(404, `Failed to file for ${request.query.id}: ${err.message}`);
                    }
                })
            }
            catch (err) {
                logger.error('Key download failed: ', err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        /**
         * Upload pem format files. These can be key, a certificate, or a file that
         * contains keys or certificates.
         */
        this._app.post('/uploadPem', (async (request: any, response) => {
            // FUTURE: Allow der and pfx files to be submitted
            if (!request.files || Object.keys(request.files).length == 0) {
                return response.status(400).json({ error: 'No file selected' });
            }
            try {
                let files: any = request.files.certFile;
                if (!Array.isArray(files)) {
                    files = [files];
                }

                let result: OperationResult = new OperationResult('multiple');

                for (let f of files) {
                    result.merge(await this._processMultiFile(f.data.toString()));
                }

                if (result.added.length + result.updated.length + result.deleted.length > 0) {
                    this._broadcast(result);
                }
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                logger.error(`Upload files failed: ${err.message}`);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        }));
        this._app.post('/api/uploadPem', async (request, response) => {
            try {
                if (request.headers['content-type'] != 'text/plain') {
                    return response.status(400).json(new OperationResult('').pushMessage('Content type must be text/plain', ResultType.Failed).getResponse());
                }
                if (!(request.body as string).includes('\n')) {
                    return response.status(400).json(new OperationResult('').pushMessage('Key must be in standard 64 byte line length format - try --data-binary with curl', ResultType.Failed).getResponse());
                }

                let result: OperationResult = await this._processMultiFile(request.body);
                this._broadcast(result);
                return response.status(200).json(result.getResponse()); 
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/ChainDownload', async (request, response) => {
            // BUG - Breaks if there chain is not complete
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let fileData = await c.getCertificateChain();
                response.type('application/text');
                response.setHeader('Content-Disposition', `attachment; filename="${c.name}_chain.pem"`);
                response.send(fileData);
            }
            catch (err) {
                logger.error('Chain download failed: ' + err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.use((request, response, _next) => {
            try {
                logger.warn(`No paths match ${request.path}`);
                response.status(404).json({
                    success: false,
                    title: 'Error',
                    messages: [
                        {
                            message: `No paths match ${ request.path }`,
                            type: ResultType.Failed
                        }
                    ]
                });
            }
            catch (err) {
                response.status(err.status ?? 500).json({ 
                    success: false,
                    title: 'Error',
                    messages: [
                        {
                            message: err.message,
                            type: ResultType.Failed
                        }
                    ]
                 });
                // response.status(err.status ?? 500).json({ error: err.message });
            }
        });

        let server: http.Server | https.Server;

        try {
            if (this._certificate) {
                const options = {
                    cert: this._certificate,
                    key: this._key,
                };
                server = https.createServer(options, this._app).listen(this._port, '0.0.0.0');
            }
            else {
                server = http.createServer(this._app).listen(this._port, '0.0.0.0');
                server.on('error', (err) => {
                    logger.fatal(`Webserver error: ${err.message}`);
                    process.exit(4);
                })
            }
            logger.info('Listening on ' + this._port);
        }
        catch (err) {
            logger.fatal(`Failed to start webserver: ${err}`);
        }

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

    /**
     * Ensures that the certificates and keys in the file system are consistent with the entries in the database and vice-versa. Thus, files found
     * in the file system that are not in the database will be added, rows found in the database that do not have matching files will be deleted.
     * 
     * @private
     * @returns Promise\<void>
     */
    private async _dbInit(): Promise<void> {
        return new Promise<void>(async (resolve, reject) => {
            try {
                let version: (DBVersionRow & LokiObj)[] = DbStores.find();

                if (version.length > 1) {
                    logger.fatal('Version table is corrupt. Should only contain one row');
                    process.exit(4);
                }
                else if (version.length == 0) {
                    DbStores.insert({ version: this._currentVersion });
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
                let files: string[];
                let certRows: CertificateUtil[] = CertificateStores.find().sort((l, r) => l.name.localeCompare(r.name));

                certRows.forEach((row) => {
                    if (!fs.existsSync(row.absoluteFilename)) {
                        logger.warn(`Certificate ${row.name} not found - removed`);
                        CertificateStores.bulkUpdate({ $loki: row.signedById }, (r) => {
                            r.signedById = null;
                            logger.warn(`Removed signedBy from ${r.name}`);
                        });

                        KeyStores.find({ pairId: row.$loki }).forEach((row) => {
                            row.clearCertificateKeyPair();
                            logger.warn(`Removed relationship to private key from ${row.name}`);
                        });
                        row.remove();
                    }
                });

                files = fs.readdirSync(CertificateStores.CertificatePath);

                let adding: Promise<OperationResult>[] = [];

                files.forEach(async (file) => {
                    let cert: CertificateUtil = CertificateStores.findOne({ $loki: CertificateUtil.getIdFromFileName(file) });
                    if (!cert) {
                        try {
                            adding.push(this._tryAddCertificate({ filename: cert.absoluteFilename }));
                        }
                        catch (err) {}
                    }
                });

                await Promise.all(adding);

                let nonRoot = CertificateStores.find( { '$and': [ { 'type': { '$ne': CertTypes.root }}, { signedById: null } ] });

                for (let r of nonRoot) {
                    let signer = await r.findSigner();

                    if (signer != null) {
                        logger.info(`${r.name} is signed by ${signer.name}`);
                        r.updateSignedById(signer.$loki);
                    }
                    else {
                        logger.warn(`${r.name} is not signed by any certificate`);
                    }
                }

                let keyRows: KeyUtil[] = KeyStores.find().sort((l, r) => l.name.localeCompare(r.name));

                for (let k of keyRows) {
                    if (!existsSync(k.absoluteFilename)) {
                        logger.warn(`Key ${k.name} not found - removed`);
                        k.remove();
                    }
                };

                files = fs.readdirSync(this._privatekeysPath);
                adding = [];

                files.forEach(async (file) => {
                    let key: KeyUtil = KeyStores.findOne({ $loki: KeyUtil.getIdFromFileName(file) });
                    if (!key) {
                        try {
                            adding.push(this._tryAddKey({ filename: path.join(this._privatekeysPath, file) }));
                        }
                        catch (err) {
                            logger.debug('WTF');
                        }
                    }
                });

                await Promise.allSettled(adding);

                this._db.saveDatabase((err) => {
                    if (err) reject(err);
                    else resolve();
                });

                await this._databaseFixUp();
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Processes a multi-file PEM string and adds the certificates or keys to the server.
     * @param pemString The multi-file PEM string to process.
     * @returns A promise that resolves to an OperationResult indicating the result of the operation.
     */
    private async _processMultiFile(pemString: string): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            let result: OperationResult = new OperationResult('multiple');
            try {
                // TODO: Put this in CertificateUtil
                let msg: pem.ObjectPEM[] = pem.decode(pemString);

                if (msg.length == 0) {
                    throw new CertError(400, 'Could not decode the file as a pem certificate');
                }

                for (let m of msg) {
                    logger.debug(`Processing ${m.type}`);
                    let oneRes: OperationResult;
                    try {
                        if (m.type.includes('CERTIFICATE')) {
                            // TODO: Put this in CertificateUtil
                            oneRes = await this._tryAddCertificate({ pemString: pem.encode(m, { maxline: 64 }) });
                        }
                        else if (m.type.includes('KEY')) {
                            // TODO: Put this in CertificateUtil
                            oneRes = await this._tryAddKey({ pemString: pem.encode(m, { maxline: 64 }) });
                        }
                        else {
                            throw new CertError(409, `Unsupported type ${m.type}`);
                        }
                        result.merge(oneRes);
                    }
                    catch (err) {
                        // logger.error(err.message);
                        result.pushMessage(err.message, ResultType.Failed);
                    }
                }
                resolve(result);
            }
            catch (err) {
                result.pushMessage(err.message, ResultType.Failed);
                resolve(result);
            }
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
    private async _tryAddCertificate(input: { filename: string, pemString?: string } | { filename?: string, pemString: string }): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                if (!input.pemString) {
                    logger.info(`Trying to add ${path.basename(input.filename)}`);
                    if (!await exists(input.filename)) {
                        reject(new CertError(404, `${path.basename(input.filename)} does not exist`));
                    }
                    input.pemString = await readFile(input.filename, { encoding: 'utf8' });
                }

                // TODO: Put this in CertificateUtil
                let msg = pem.decode(input.pemString)[0];
                logger.debug(`Received ${msg.type}`);

                if (msg.type != 'CERTIFICATE') {
                    throw new CertError(400, 'Unsupported type ' + msg.type);
                }

                let result: OperationResult = new OperationResult('');
                let cRow = await CertificateUtil.createFromPem(input.pemString);
                logger.debug(`Adding certificate ${cRow.name}`);
                result.name = cRow.name;
                result.merge(await cRow.insert());
                result.pushMessage(`Certificate ${cRow.name} added`, ResultType.Success);
                logger.info(`Certificate ${cRow.name} added`);
                cRow.writeFile();
                logger.info(`Written file ${cRow.name}`)
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

   /**
    * Tries to delete a certificate and breaks all the links it has with other certificates and keys if any.
    * 
    * @param c The row of the certificate to delete
    * @returns A synopsis of the database updates made as a result of this deletion
    */
    private async _tryDeleteCert(c: CertificateUtil): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                if (!await c.deleteFile()) {
                    logger.error(`Could not find file ${c.absoluteFilename}`);
                }
                else {
                    logger.debug(`Deleted file ${c.absoluteFilename}`);
                }

                resolve(await c.remove());
                logger.debug(`Removed row ${c.name}`);
            }
            catch (err) {
                reject(err);
            }
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
    private async _tryAddKey(input: { filename: string, pemString?: string, password?: string } | { filename?: string, pemString: string, password?: string }): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                if (!input.pemString) {
                    logger.info(`Trying to add ${path.basename(input.filename)}`);
                    if (!await exists(input.filename)) {
                        throw new CertError(404, `${path.basename(input.filename)} does not exist`);
                        return;
                    }
                    input.pemString = await readFile(input.filename, { encoding: 'utf8' });
                }
                let result: OperationResult = new OperationResult('unknown_key');
                let kRow: KeyUtil = await KeyUtil.CreateFromPem(input.pemString, input.password);

                // See if we already have this key
                let match: KeyUtil;
                if ((match = KeyStores.isIdentical(kRow))) {
                    throw new CertError(409, `Key already present: ${match.name}`);
                }

                // Generate a file name for a key without a certificate
                if (kRow.pairId == null) {
                    result.name = 'unknown_key';
                }
                else {
                    result.name = kRow.name;
                }
                let temp: OperationResult = kRow.insert();
                result.merge(temp);
                result.pushMessage(`Key ${kRow.name} added`, ResultType.Success);

                if (temp.pushUpdated.length > 0) {
                    result.name = temp.name;
                }
                logger.info('Inserted key ' + kRow.name);
                await kRow.writeFile();
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
        });
    }

    /**
     * Deletes a key's pem file and removes it from the database. If this key has a certificate pair that the certificate will be
     * updated to show that it no longer has its key pair in the system.
     * 
     * @param k Key to delete
     * @returns Summary of modifications to the database
     */
    private _tryDeleteKey(k: KeyUtil): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                if (!await k.deleteFile()) {
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
        });
    }

    /**
     * Broadcasts the updates to the certificates and keys to all of the web clients
     * 
     * @param data the collection of operation results
     */
    private _broadcast(data: OperationResult): void {
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
    private _resolveCertificateQuery(query: QueryType): CertificateUtil {
        let c: CertificateUtil[];

        if ('name' in query && 'id' in query) throw new CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query)) throw new CertError(400, 'Name or id must be specified');
        
        let selector = ('name' in query)? { name: query.name as string } : { $loki: parseInt(query.id as string)};

        if (selector.$loki && isNaN(selector.$loki)) throw new CertError(400, 'Specified id is not numeric');

        c = CertificateStores.find(selector);

        if (c.length == 0) {
            throw new CertError(404, `No certificate for ${query.id ? 'id' : 'name'} ${Object.values(selector)[0]} found`);
        }
        else if (c.length > 1) {
            throw new CertMultiError(400, `Multiple certificates match the name ${Object.values(selector)[0]} - use id instead`, c.map((l) => l.$loki));
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
    private _resolveCertificateUpdate(query: QueryType, updater: (row: CertificateUtil) => void): OperationResult {
        if ('name' in query && 'id' in query) throw new CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query)) throw new CertError(400, 'Name or id must be specified');
        let selector = ('name' in query)? { name: query.name as string } : { $loki: parseInt(query.id as string)};

        let c: CertificateUtil[] = CertificateStores.find(selector);

        if (c.length == 0) {
            throw new CertError(404, `No certificate for ${query.id ? 'id' : 'name'} ${Object.values(selector)[0]} found`);
        }
        else if (c.length > 1) {
            throw new CertError(400, `Multiple certificates match the name ${Object.values(selector)[0]} - use id instead`);
        }

        let result = new OperationResult(c[0].subject.CN);

        result.pushUpdated(new OperationResultItem(c[0].type, c[0].$loki));
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
    private _resolveKeyQuery(query: QueryType): KeyUtil {
        let k: KeyUtil[];
        let selector: any;

        if (query.name && query.id) throw new CertError(422, 'Name and id are mutually exclusive');
        if (!query.name && !query.id) throw new CertError(400, 'Name or id must be specified');
        
        if (query.name) {
            selector = { name: query.name };
        }
        else if (query.id) {
            let id: number = parseInt(query.id);

            if (isNaN(id)) throw new CertError(400, 'Specified id is not numeric');
            selector = { $loki: id };
        }

        k = KeyStores.find(selector);

        if (k.length == 0) {
            throw new CertError(404, `No key for ${JSON.stringify(query)} found`);
        }
        else if (k.length > 1) {
            throw new CertMultiError(400, `Multiple keys match the CN ${JSON.stringify(query)} - use id instead`, k.map((l) => l.$loki));
        }

        return k[0];
    }

    /**
     * This function is used to update the database when breaking changes are made. 
     */
    private async _databaseFixUp(): Promise<void> {

        // First check that the database is a version that can be operated upon by the code.
        if (this._currentVersion < 4) {
            console.error(`Database version ${this._currentVersion} is not supported by the release - try installing the previous minor version`);
            process.exit(4);
        }
        // this._certificates.find({ $and: [{ signedById: null }, { type: 1 }] }).forEach(r => logger.warn(`Bad signed (${r.$loki}): ${r.subject.CN} - fixing`));
        // this._certificates.chain().find({ $and: [ { signedById: null }, { type: 1 } ] }).update((r) => r.signedById = r.$loki);

        // Check that the database is an older version that needs to be modified
        logger.info('Database is a supported version for this release');
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
    private static _guessOs(userAgent: string): userAgentOS {

        if (userAgent === null || userAgent === '') return userAgentOS.UNKNOWN;

        let ua = userAgent.toLowerCase();

        if (ua.includes('powershell')) return userAgentOS.WINDOWS;      // Powershell will always be treated as Windows
        if (ua.includes('windows')) return userAgentOS.WINDOWS;
        if (ua.includes('linux')) return userAgentOS.LINUX;
        if (ua.includes('curl')) return userAgentOS.LINUX;              // Best guess
        if (ua.includes('wget')) return userAgentOS.LINUX               // Another best guess
        if (ua.includes('mac')) return userAgentOS.MAC;
        if (ua.includes('x11')) return userAgentOS.LINUX;
        if (ua.includes('iphone')) return userAgentOS.IPHONE;
        if (ua.includes('android')) return userAgentOS.ANDROID;
        return userAgentOS.UNKNOWN;
    }

    /**
     * Validates RNA strings to ensure they consist only of characters allowed in those strings. The node-forge package does not enforce this.
     * 
     * @param rnas Array of RNA values for validation
     * @returns {{valid: boolean, message?: string}} valid: true if all are valid otherwise valid: false, message: error message
     */
    // private static _isValidRNASequence(rnas: string[]): { valid: boolean, message?: string } {
    //     for (let r in rnas) {
    //         if (!/^[a-z A-Z 0-9'\=\(\)\+\,\-\.\/\:\?]*$/.test(rnas[r])) {
    //             return { valid: false, message: 'Subject contains an invalid character' };
    //         }
    //     }
    //     return { valid: true };
    // }

    /**
     * Add subject values to pki.CertificateField
     * 
     * @param subject Subject fields for the certificate
     * @returns pki.CertificateField with the provided fields
     */
    // private static _setAttributes(subject: CertificateSubject): pki.CertificateField[] {
    //     let attributes: pki.CertificateField[] = [];
    //     if (subject.C)
    //         attributes.push({ shortName: 'C', value: subject.C });
    //     if (subject.ST)
    //         attributes.push({ shortName: 'ST', value: subject.ST });
    //     if (subject.L)
    //         attributes.push({ shortName: 'L', value: subject.L });
    //     if (subject.O)
    //         attributes.push({ shortName: 'O', value: subject.O });
    //     if (subject.OU)
    //         attributes.push({ shortName: 'OU', value: subject.OU });
    //     attributes.push({ shortName: 'CN', value: subject.CN });

    //     return attributes;
    // }

    /**
     * Generates a certificate serial number
     * 
     * @returns A random number to use as a certificate serial number
     */
    // private static  _getRandomSerialNumber(): string {
    //     return WebServer._makeNumberPositive(util.bytesToHex(random.getBytesSync(20)));
    // }

    /**
     * If the passed number is negative it is made positive
     * 
     * @param hexString String containing a hexadecimal number
     * @returns Positive version of the input
     */
    // private static _makeNumberPositive = (hexString: string): string => {
    //     let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);

    //     if (mostSignificativeHexDigitAsInt < 8)
    //         return hexString;

    //     mostSignificativeHexDigitAsInt -= 8;
    //     return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
    // };
}

