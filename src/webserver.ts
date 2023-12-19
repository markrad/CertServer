import { existsSync, mkdirSync } from 'node:fs';
import path from 'path';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { readFile, writeFile, unlink, rename } from 'fs/promises'
import crypto from 'crypto';

import { jsbn, pki, pem, util, random, md } from 'node-forge'; 
import loki, { Collection, LokiFsAdapter } from 'lokijs'
import Express, { NextFunction } from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';
import WsServer from 'ws';
import { Readable } from 'stream';
import * as log4js from 'log4js';

import { EventWaiter } from './utility/eventWaiter';
import { exists } from './utility/exists';
import { ExtensionParent } from './extensions/ExtensionParent';
import { ExtensionBasicConstraints } from './extensions/ExtensionBasicConstraints';
import { ExtensionKeyUsage } from './extensions/ExtensionKeyUsage';
import { ExtensionAuthorityKeyIdentifier } from './extensions/ExtensionAuthorityKeyIdentifier';
import { ExtensionSubjectKeyIdentifier } from './extensions/ExtensionSubjectKeyIdentifier';
import { ExtensionExtKeyUsage } from './extensions/ExtensionExtKeyUsage';
import { ExtensionSubjectAltName, ExtensionSubjectAltNameOptions } from './extensions/ExtensionSubjectAltName';
import { OperationResult } from './webservertypes/OperationResult';
import { OperationResultItem } from './webservertypes/OperationResultItem';
import { CertTypes } from './webservertypes/CertTypes';
import { Config } from './webservertypes/Config';
import { CertificateSubject } from './webservertypes/CertificateSubject';
import { CertificateRow } from './webservertypes/CertificateRow';
import { PrivateKeyRow } from './webservertypes/PrivateKeyRow';
import { DBVersionRow } from './webservertypes/DBVersionRow';
import { CertificateLine } from './webservertypes/CertificateLine';
import { CertificateBrief } from './webservertypes/CertificateBrief';
import { KeyBrief } from './webservertypes/KeyBrief';
import { GenerateCertRequest } from './webservertypes/GenerateCertRequest';
import { GenerateNonRootCertRequest } from './webservertypes/GenerateNonRootCertRequest';
import { QueryType } from './webservertypes/QueryType';
import { userAgentOS } from './webservertypes/userAgentOS';
import { CertError } from './webservertypes/CertError';

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
    private _certificates: Collection<CertificateRow>;
    private _privateKeys: Collection<PrivateKeyRow>;
    private _dbVersion: Collection<DBVersionRow>;
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

        // this._cache = new CertificateCache(this._certificatesPath, 10 * 60 * 60);
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
            this._certificates = certificates;
            this._privateKeys = privateKeys;
            this._dbVersion = dbVersion;
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
        this._app.use(Express.text({ type: 'application/json' }));
        this._app.use('/scripts', Express.static(path.join(__dirname, '../../web/scripts')));
        this._app.use('/styles', Express.static(path.join(__dirname, '../../web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, '../../web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, '../../web/files')));
        this._app.use('/images', Express.static(path.join(__dirname, '../../web/images')));
        this._app.use(FileUpload());
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
        this._app.get('/api/helper', (request, response) => {
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

            let readable: Readable;

            if (os == userAgentOS.LINUX || os == userAgentOS.MAC) {
                response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.sh"`);
                readable = Readable.from([
                    `function getcert(){ wget --content-disposition ${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/getCertificatePem?id=$@; }\n`,
                    `function getkey(){ wget --content-disposition ${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/getKeyPem?id=$@; }\n`,
                    `function getchain(){ wget --content-disposition ${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/chainDownload?id=$@; }\n`,
                    `function pushcert(){ curl -X POST -H "Content-Type: text/plain" --data-binary @$@ ${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/uploadCert; }\n`,
                    `function pushkey(){ curl -X POST -H "Content-Type: text/plain" --data-binary @$@ ${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/uploadKey; }\n`
                ]);
            }
            else if (os == userAgentOS.WINDOWS) {
                response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.ps1"`);
                readable = Readable.from([
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
                        `return "${csHost({ protocol: this._certificate? 'https' : 'http', hostname: request.hostname, port: this._port })}/api/"\n`,
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
                return response.status(400).json({ error: `No script for OS ${userAgentOS[os]}}` });
            }
            readable.pipe(response);
        })
        this._app.post('/createCACert', async (request, _response, next) => {
            request.url = '/api/createCACert'
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
        this._app.post('/updateCertTag', async (request, _response, next) => {
            request.url = '/api/updateCertTag';
            request.query['id'] = request.body.toTag;
            next();
        });
        /**
         * Upload pem format files. These can be key, a certificate, or a file that
         * contains keys or certificates.
         */
        this._app.post('/uploadCert', (async (request: any, response) => {
            // FUTURE: Allow der and pfx files to be submitted
            if (!request.files || Object.keys(request.files).length == 0) {
                return response.status(400).json({ error: 'No file selected' });
            }
            try {
                let mergeResults: (accumulator: OperationResult, next: OperationResult) => OperationResult = (accumulator: OperationResult, next: OperationResult) => {
                    let i: string;
                    for (i in next.added) {
                        if (!accumulator.added.some((a) => a.type == next.added[i].type && a.id == next.added[i].id)) {
                            accumulator.added.push(next.added[i]);
                        }
                    }

                    for (i in next.updated) {
                        if (!accumulator.updated.some((a) => a.type == next.updated[i].type && a.id == next.updated[i].id)) {
                            accumulator.updated.push(next.updated[i]);
                        }
                    }

                    for (i in next.deleted) {
                        if (!accumulator.deleted.some((a) => a.type == next.deleted[i].type && a.id == next.deleted[i].id)) {
                            accumulator.deleted.push(next.deleted[i]);
                        }
                    }

                    return accumulator;
                }
                let files: any = request.files.certFile;
                if (!Array.isArray(files)) {
                    files = [ files ];
                }

                let result: OperationResult = { name: 'multiple', added: [], updated: [], deleted: [] };
                type message = { level: number, message: string };
                let messages: message[] = [];

                for (let i in files) {
                    let msg: pem.ObjectPEM[] = pem.decode(files[i].data);

                    for (let j in msg) {
                        logger.debug(`Received ${msg[j].type}`);
                        try {
                            let oneRes: OperationResult = null;
                            if (msg[j].type.includes('CERTIFICATE')) {
                                oneRes = await this._tryAddCertificate({ filename: files[i].name, pemString: pem.encode(msg[j], { maxline: 64 }) });
                                messages.push({ level: 0, message: `Certificate ${files[i].name} uploaded` });
                            }
                            else if (msg[j].type.includes('KEY')) {
                                oneRes = await this._tryAddKey({ filename: files[i].name, pemString: files[i].data.toString() });
                                messages.push({ level: 0 , message: `Key ${files[i].name} uploaded` });
                            }
                            else {
                                throw new CertError(409, `File ${files[i].name} is not a certificate or a key`);
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
                return response.status(err.status?? 500).json({ error: err.message });
            }
        }));
        this._app.delete('/deleteCert', ((request: any, _response: any, next: NextFunction) => {
            request.url = '/api/deleteCert';
            next();
        }));
        this._app.get('/certList', (request, _response, next) => {
            request.url = '/api/certList';
            next();
        });
        this._app.get('/certDetails', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let retVal: CertificateBrief = this._getCertificateBrief(c as CertificateRow & LokiObj);
                response.status(200).json(retVal);
            }
            catch (err) {
                response.status(err.status ?? 500).json({ error: err.message })
            }
        });
        // this._app.post('/uploadKey', async (request: any, response) => {
        //     if (!request.files || Object.keys(request.files).length == 0) {
        //         return response.status(400).json({ error: 'No file selected' });
        //     }
        //     try {
        //         let result: OperationResult = await this._tryAddKey({ pemString: request.files.keyFile.data.toString(), password: request.query.password });
        //         this._broadcast(result);
        //     }
        //     catch (err) {
        //         return response.status(err.status ?? 500).json({ error: err.message });
        //     }
        // });
        this._app.delete('/deleteKey', ((request, _response, next: NextFunction) => {
            request.url = '/api/deleteKey';
            next();
        }))
        this._app.get('/keyList', (request, _response, next) => {
            request.url = '/certList';
            next();
        });
        this._app.get('/keyDetails', async (request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                if (k) {
                    let retVal: KeyBrief = this._getKeyBrief(k);
                    response.status(200).json(retVal);
                }
                else {
                    response.status(404).json({ error: 'Key not found' });
                }
            }
            catch (err) {
                response.status(err.status ?? 500).json({ error: err.message });
            }
        });
        this._app.post('/api/createCaCert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body: GenerateCertRequest = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.validFrom? new Date(body.validFrom) : new Date();
                let validTo: Date = body.validTo? new Date(body.validTo) : null;
                let subject: CertificateSubject = {
                    C: body.country,
                    ST: body.state,
                    L: body.location,
                    O: body.organization,
                    OU: body.unit,
                    CN: body.commonName
                };

                let errString: string[] = [];

                if (!subject.CN) errString.push('Common name is required');
                if (!validTo) errString.push('Valid to is required');
                if (body.country.length > 0 && body.country.length != 2) errString.push('Country code must be omitted or have two characters');
                let rc: { valid: boolean, message?: string } = WebServer._isValidRNASequence([ body.country, body.state, body.location, body.unit, body.commonName ]);
                if (!rc.valid) errString.push(rc.message);

                if (errString.length > 0) {
                    return response.status(400).json({ error: errString.join('; ') })
                }

                // Create an empty Certificate
                let cert = pki.createCertificate();

                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._setAttributes(subject);
                const extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: true, critical: true }),
                    new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, keyIdentifier: true }),
                    new ExtensionSubjectKeyIdentifier({ }),
                ]
        
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
                let certResult = await this._tryAddCertificate({ pemString: pki.certificateToPem(cert) });
                let keyResult = await this._tryAddKey({ pemString: pki.privateKeyToPem(privateKey) });
                certResult.added = certResult.added.concat(keyResult.added);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                return response.status(200)
                    .json({ message: `Certificate/Key ${certResult.name} added`, types: [ CertTypes[CertTypes.root], CertTypes[CertTypes.key] ].join(';') });
            }
            catch (err) {
                return response.status(500).json({ error: err.message })
            }
        });
        this._app.post('/api/createIntermediateCert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body: GenerateNonRootCertRequest = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.validFrom? new Date(body.validFrom) : new Date();
                let validTo: Date = body.validTo? new Date(body.validTo) : null;
                let subject: CertificateSubject = {
                    C: body.country,
                    ST: body.state,
                    L: body.location,
                    O: body.organization,
                    OU: body.unit,
                    CN: body.commonName
                };
                let errString: string[] = [];

                if (!subject.CN) errString.push('Common name is required');
                if (!validTo) errString.push('Valid to is required');
                if (!body.signer) errString.push('Signing certificate is required');
                if (body.country.length > 0 && body.country.length != 2) errString.push('Country code must be omitted or have two characters');
                let rc: { valid: boolean, message?: string } = WebServer._isValidRNASequence([ body.country, body.state, body.location, body.unit, body.commonName ]);
                if (!rc.valid) errString.push(rc.message);

                if (errString.length > 0) {
                    return response.status(400).json({ error: errString.join('\n') })
                }

                const cRow = this._certificates.findOne({ $loki: parseInt(body.signer) });
                const kRow = this._privateKeys.findOne({ $loki: cRow.keyId });

                if (!cRow) {
                    return response.status(404).json({ error: 'Could not find signing certificate'});
                }
                if (!kRow) {
                    return response.status(404).json({ error: 'Could not find signing certificate\'s private key'});
                }

                const c: pki.Certificate = await this._pkiCertFromRow(cRow);
                // const c = pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(cRow)), { encoding: 'utf8' }));
                const k: pki.PrivateKey = await(this._pkiKeyFromRow(kRow, body.password));

                // Create an empty Certificate
                let cert = pki.createCertificate();
        
                // const ski: any = c.getExtension({ name: 'subjectKeyIdentifier' });
                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._setAttributes(subject);
                let sal:ExtensionSubjectAltNameOptions = { domains: [ subject.CN ] };
                if (body.SANArray != undefined) {
                    // Add alternate subject names or IPs
                    let SANArray = Array.isArray(body.SANArray)? body.SANArray : [ body.SANArray ];
                    let domains = SANArray.filter((entry: string) => entry.startsWith('DNS:')).map((entry: string) => entry.split(' ')[1]);
                    let ips = SANArray.filter((entry: string) => entry.startsWith('IP:')).map((entry: string) => entry.split(' ')[1]);
                    if (domains.length > 0) sal.domains = sal.domains.concat(domains);
                    if (ips.length > 0) sal['IPs'] = ips;
                    logger.debug(sal.domains);
                    logger.debug(sal.IPs);
                }
                const extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: true, critical: true }),
                    new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }),
                    // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, keyIdentifier: true, serialNumber: ski['subjectKeyIdentifier'] }),
                    new ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
                    // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, serialNumber: c.serialNumber }),
                    // new ExtensionAuthorityKeyIdentifier({ /*authorityCertIssuer: true, keyIdentifier: true,*/ serialNumber: ski['subjectKeyIdentifier'] }),
                    // new ExtensionAuthorityKeyIdentifier({ authorityCertIssuer: true, keyIdentifier: true, authorityCertSerialNumber: true }),
                    new ExtensionSubjectKeyIdentifier({ }),
                    new ExtensionSubjectAltName(sal),
                ]
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
                let certResult = await this._tryAddCertificate({ pemString: pki.certificateToPem(cert) });
                let keyResult = await this._tryAddKey({ pemString: pki.privateKeyToPem(privateKey) });
                certResult.added = certResult.added.concat(keyResult.added);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                return response.status(200)
                    .json({ message: `Certificate/Key ${certResult.name} added` });
            }
            catch (err) {
                logger.error(`Failed to create intermediate certificate: ${err.message}`);
                return response.status(500).json({ error: err.message });
            }
        });
        this._app.post('/api/createLeafCert', async (request, response) => {
            try {
                logger.debug(request.body);
                let body: GenerateNonRootCertRequest = typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                let validFrom: Date = body.validFrom? new Date(body.validFrom) : new Date();
                let validTo: Date = body.validTo? new Date(body.validTo) : null;
                let subject: CertificateSubject = {
                    C: body.country,
                    ST: body.state,
                    L: body.location,
                    O: body.organization,
                    OU: body.unit,
                    CN: body.commonName
                };
                let errString: string[] = [];

                if (!subject.CN) errString.push('Common name is required');
                if (!validTo) errString.push('Valid to is required');
                if (!body.signer) errString.push('Signing certificate is required');
                if (body.country.length > 0 && body.country.length != 2) errString.push('Country code must be omitted or have two characters');
                let rc: { valid: boolean, message?: string } = WebServer._isValidRNASequence([ body.country, body.state, body.location, body.unit, body.commonName ]);
                if (!rc.valid) errString.push(rc.message);

                if (errString.length > 0) {
                    return response.status(400).json({ error: errString.join('\n') })
                }

                const cRow = this._certificates.findOne({ $loki: parseInt(body.signer) });
                const kRow = this._privateKeys.findOne({ pairId: cRow.$loki });

                if (!cRow || !kRow) {
                    return response.status(500).json({ error: 'Unexpected database corruption - rows missing'});
                }

                const c = pki.certificateFromPem(fs.readFileSync(path.join(this._certificatesPath, WebServer._getCertificateFilenameFromRow(cRow)), { encoding: 'utf8' }));
                let k: pki.PrivateKey;

                if (c) {
                    if (body.password) {
                        k = pki.decryptRsaPrivateKey(fs.readFileSync(path.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }), body.password);
                    }
                    else {
                        k = pki.privateKeyFromPem(fs.readFileSync(path.join(this._privatekeysPath, WebServer._getKeyFilenameFromRow(kRow)), { encoding: 'utf8' }));
                    }
                }
                // const ski: any = c.getExtension({ name: 'subjectKeyIdentifier' });
                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = WebServer._setAttributes(subject);
                let sal:ExtensionSubjectAltNameOptions = { domains: [ subject.CN ] };
                if (body.SANArray != undefined) {
                    // Add alternate subject names or IPs
                    let SANArray = Array.isArray(body.SANArray)? body.SANArray : [ body.SANArray ];
                    let domains = SANArray.filter((entry: string) => entry.startsWith('DNS:')).map((entry: string) => entry.split(' ')[1]);
                    let ips = SANArray.filter((entry: string) => entry.startsWith('IP:')).map((entry: string) => entry.split(' ')[1]);
                    if (domains.length > 0) sal.domains = sal.domains.concat(domains);
                    if (ips.length > 0) sal['IPs'] = ips;
                    logger.debug(sal.domains);
                    logger.debug(sal.IPs);
                }
                let extensions: ExtensionParent[] = [
                    new ExtensionBasicConstraints({ cA: false }),
                    new ExtensionSubjectKeyIdentifier({ }),
                    new ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }),
                    // new ExtensionAuthorityKeyIdentifier({ /*authorityCertIssuer: true, keyIdentifier: true,*/ serialNumber: ski['subjectKeyIdentifier'] }),
                    new ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }),
                    new ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true,  }),
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
                let certResult = await this._tryAddCertificate({ pemString: pki.certificateToPem(cert) });
                let keyResult = await this._tryAddKey({ pemString: pki.privateKeyToPem(privateKey) });
                certResult.added = certResult.added.concat(keyResult.added);
                certResult.name = `${certResult.name}/${keyResult.name}`;
                this._broadcast(certResult);
                return response.status(200)
                    .json({ message: `Certificate/Key ${certResult.name}/${keyResult.name} added` });
            }
            catch (err) {
                logger.error(`Error creating leaf certificate: ${err.message}`);
                return response.status(500).json({ error: err.message })
            }
        });
        this._app.get('/api/certName', async(request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                response.status(200).json({ name: c.subject.CN, id: c.$loki, tags: c.tags });
            }
            catch (err) {
                response.status(err.status ?? 500).json({ error: err.message });
            }
        });
        this._app.get('/api/keyList', (request, _response, next) => {
            request.url = '/api/certList';
            request.query = { type: 'key' };
            next();
        });
        this._app.get('/api/certList', (request, response) => {
            let type: CertTypes = CertTypes[(request.query.type as any)] as unknown as CertTypes;

            if (type == undefined) {
                response.status(404).json({ error: `Directory ${request.query.type} not found` });
            }
            else {
                let retVal: CertificateLine[] = [];
                if (type != CertTypes.key) {
                    retVal = this._certificates.chain().find({ type: type }).sort((l, r) => l.name.localeCompare(r.name)).data().map((entry) => { 
                        return { name: entry.subject.CN, type: CertTypes[type].toString(), id: entry.$loki, tags: entry.tags?? [], keyId: entry.keyId }; 
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
                            type: CertTypes[type].toString(), 
                            id: entry.$loki 
                        };
                    });
                }
                response.status(200).json({ files: retVal });
            }
        });
        this._app.get('/api/getCertificatePem', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);

                response.download(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), c.name + '.pem', (err) => {
                    if (err) {
                        return response.status(500).json({ error: `Failed to file for ${request.query}: ${err.message}` });
                    }
                })
            }
            catch (err) {
                logger.error('Certificate download failed: ', err.message);
                return response.status(err.status?? 500).json({ error: err.message });
            }
        });
        this._app.post('/api/uploadCert', async (request: any, response) => {
            // FUTURE Allow multiple concatenated pem files
            // FUTURE Merge uploadCert and uploadKey into uploadFile
            if (request.headers['content-type'] != 'text/plain') {
                return response.status(400).json({ error: 'Content-Type must be text/plain' });
            }
            if (!(request.body as string).includes('\n')) {
                return response.status(400).json({ error: 'Certificate must be in standard 64 byte line length format - try --data-binary with curl' });
            }
            try {
                let result: OperationResult = await this._tryAddCertificate({ pemString: request.body });
                this._broadcast(result);
                return response.status(200).json({ message: `Certificate ${result.name} added` });
            }
            catch (err) {
                response.status(err.status?? 500).json({ error: err.message });
            }
        });
        this._app.delete('/api/deleteCert', async (request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let result: OperationResult = await this._tryDeleteCert(c);
                this._broadcast(result);
                return response.status(200).json({ message: `Certificate ${result.name} deleted` });
            }
            catch (err) {
                return response.status(err.status?? 500).json(JSON.stringify({ error: err.message }));
            }
        });
        this._app.post('/api/updateCertTag', async (request, response) => {
            try {
                let tags: { tags: string[] } =  typeof request.body == 'string'? JSON.parse(request.body) : request.body;
                if (tags.tags === undefined) tags.tags = []
                else if (!Array.isArray(tags.tags)) tags.tags = [ tags.tags ];
                let cleanedTags: string[] = tags.tags.map((t) => t.trim()).filter((t) => t != '');
                for (let tag in cleanedTags) {
                    if (tag.match(/[;<>\(\)\{\}\/]/) !== null) throw new CertError(400, 'Tags cannot contain ; < > / { } ( )');
                }
                let result: OperationResult = this._resolveCertificateUpdate(request.query as QueryType, (c) => {
                    c.tags = cleanedTags;
                });
                this._broadcast(result);
                return response.status(200).json({ message: `Certificate tags updated` });
            }
            catch (err) {
                return response.status(err.status?? 500).json({ error: err.message });
                // return response.status(err.status?? 500).json(`{"error": "${err.message}"}`);
            }
        });
        this._app.get('/api/keyname', async(request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                response.status(200).json({ name: k.name, id: k.$loki, tags: [] });
            }
            catch (err) {
                response.status(err.status ?? 500).json({ error: err.message });
            }
        });
        this._app.post('/api/uploadKey', async (request, response) => {
            try {
                // if (typeof request.body != 'string') {
                if (request.headers['content-type'] != 'text/plain') {
                        return response.status(400).send('Content type must be text/plain');
                }
                if (!(request.body as string).includes('\n')) {
                    return response.status(400).send('Key must be in standard 64 byte line length format - try --data-binary with curl');
                }
                let result: OperationResult = await this._tryAddKey({ pemString: request.body, password: request.query.password as string });
                this._broadcast(result);
                // TODO: I don't think type is used any longer
                return response.status(200).json({ message: `Key ${result.name} added` });
            }
            catch (err) {
                response.status(500).json({ error: err.message });
            }
        });
        this._app.delete('/api/deleteKey', async (request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                let result: OperationResult = await this._tryDeleteKey(k);
                this._broadcast(result);
                return response.status(200).json({ message: `Key ${result.name} deleted` });
            }
            catch (err) {
                return response.status(err.status?? 500).json({ error: err.message });
            }
        });
        this._app.get('/api/getKeyPem', async (request, response) => {

            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                response.download(this._getKeysDir(WebServer._getKeyFilenameFromRow(k)), k.name + '.pem', (err) => {
                    if (err) {
                        return response.status(500).json({ error: `Failed to file for ${request.query.id}: ${err.message}` });
                    }
                })
            }
            catch (err) {
                logger.error('Key download failed: ', err.message);
                return response.status(err.status?? 500).json({ error: err.message });
            }
        });
        this._app.get('/api/ChainDownload', async (request, response) => {
            // BUG - Breaks if there chain is not complete
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                let fileData = await this._getChain(c);
                response.type('application/text');
                response.setHeader('Content-Disposition', `inline; filename=${WebServer._getCertificateFilenameFromRow(c)}_chain.pem`);
                response.send(fileData);
            }
            catch (err) {
                logger.error('Chain download failed: ' + err.message);
                return response.status(err.status?? 500).json({ error: err.message });
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
     * Initializes the database from the file system and cleans up the file system.
     * 
     * @private
     * @returns Promise\<void>
     */
    private async _dbInit(): Promise<void> {
        return new Promise<void>(async (resolve, reject) => {
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
                let files: string[];
                let certRows: (CertificateRow & LokiObj)[] = this._certificates.chain().simplesort('name').data();

                certRows.forEach((row) => {
                    if (!fs.existsSync(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(row)))) {
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

                files = fs.readdirSync(this._certificatesPath);

                let adding: Promise<OperationResult>[] = [];

                files.forEach(async (file) => {
                    let cert = this._certificates.findOne({ $loki: WebServer._getIdFromFileName(file) });
                    if (!cert) {
                        try {
                            adding.push(this._tryAddCertificate({ filename: this._getCertificatesDir(file) }));
                        }
                        catch (err) {}
                    }
                });

                await Promise.all(adding);

                let nonRoot = this._certificates.find( { '$and': [ { 'type': { '$ne': CertTypes.root }}, { signedById: null } ] });

                for (let i: number = 0; i < nonRoot.length; i++) {
                    let signer = await this._findSigner(pki.certificateFromPem(fs.readFileSync(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(nonRoot[i])), { encoding: 'utf8' })));
                    if (signer != null) {
                        logger.info(`${nonRoot[i].name} is signed by ${signer.name}`);
                        // nonRoot[i].signedBy = signer.serialNumber;
                        nonRoot[i].signedById = signer.$loki;
                        this._certificates.update(nonRoot[i]);
                    }
                }

                let keyRows: (PrivateKeyRow & LokiObj)[] = this._privateKeys.chain().simplesort('name').data();

                keyRows.forEach((key) => {
                    if (!existsSync(this._getKeysDir(WebServer._getKeyFilenameFromRow(key)))) {
                        logger.warn(`Key ${key.name} not found - removed`);
                        this._privateKeys.remove(key);
                    }
                });

                files = fs.readdirSync(this._privatekeysPath);

                adding = [];
                files.forEach(async (file) => {
                    // logger.debug(path.basename(file));
                    let key = this._privateKeys.findOne({ $loki: WebServer._getIdFromFileName(file) });
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

                let msg = pem.decode(input.pemString)[0];
                logger.debug(`Received ${msg.type}`);

                if (msg.type != 'CERTIFICATE') {
                    throw new CertError(400, 'Unsupported type ' + msg.type);
                }

                let result: OperationResult = { name: '', added: [], updated: [], deleted: [] };
                let c: pki.Certificate = pki.certificateFromPem(input.pemString);
                logger.debug(`Adding certificate ${c.subject.getField('CN').value}`);
                let signedById: number = null;

                // See if we already have this certificate
                let fingerprint256 = new crypto.X509Certificate(input.pemString).fingerprint256;

                if (this._certificates.findOne({ fingerprint256: fingerprint256 }) != null) {
                    throw new CertError(409, `${c.subject.getField('CN').value} serial number ${c.serialNumber} is a duplicate - ignored`);
                }

                // See if this is a root, intermediate, or leaf
                let type: CertTypes;
                if (c.isIssuer(c)) {
                    type = CertTypes.root;
                    signedById = -1;
                }
                else {
                    let bc: any = c.getExtension('basicConstraints');

                    if ((bc != null) && (bc.cA ?? false) == true && (bc.pathlenConstraint ?? 1) > 0) {
                        type = CertTypes.intermediate;
                    }
                    else {
                        type = CertTypes.leaf;
                    }

                    // See if any existing certificates signed this one
                    let signer = await this._findSigner(c);

                    if (signer != null) {
                        signedById = signer.$loki;
                    }
                }

                // Generate a filename for the common name
                let name = WebServer._sanitizeName(c.subject.getField('CN').value);
                result.name = c.subject.getField('CN').value;

                logger.info(`Certificate ${name} added`);
                // This is declared as returning the wrong type hence cast below
                let newRecord: CertificateRow & LokiObj = (this._certificates.insert({ 
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
                    fingerprint: new crypto.X509Certificate(input.pemString).fingerprint,
                    fingerprint256: fingerprint256,
                    tags: [], 
                    keyId: null
                })) as CertificateRow & LokiObj;    // Return value erroneously omits LokiObj

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
                if (type != CertTypes.leaf) {
                    // Update certificates that this one signed
                    let list: OperationResultItem[] = await this._findSigned(c, newRecord.$loki);

                    result.updated = result.updated.concat(list);
                }

                // See if we have a private key for this certificate
                let keys: (PrivateKeyRow & LokiObj)[] = this._privateKeys.chain().find({ pairId: null }).data();

                for (let i in keys) {
                    if (WebServer._isKeyPair(c, keys[i].n, keys[i].e)) {
                        logger.info('Found private key for ' + name);
                        await rename(this._getKeysDir(WebServer._getKeyFilenameFromRow(keys[i])), this._getKeysDir(WebServer._getKeyFilename(name + '_key', keys[i].$loki)));
                        keys[i].name = name + '_key';
                        keys[i].pairId = newRecord.$loki;
                        this._privateKeys.update(keys[i]);
                        result.updated.push({ type: CertTypes.key, id: keys[i].$loki });
                        newRecord.keyId = keys[i].$loki;
                        this._certificates.update(newRecord);
                        break;
                    }
                }

                // This guarantees a unique filename
                let newName = WebServer._getCertificateFilenameFromRow(newRecord);
                await writeFile(this._getCertificatesDir(newName), input.pemString, { encoding: 'utf8' });
                logger.info(`Written file ${newName}`)
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
     * Returns details of the certificate for display on the client browser.
     * 
     * @param c Certificate row of the certificate requested
     * @returns The useful fields from the certificate row
     */
    private _getCertificateBrief(c: CertificateRow & LokiObj): CertificateBrief {
        let c2: CertificateRow & LokiObj = null;
        if (c.signedById != null) {
            c2 = this._certificates.findOne({ $loki: c.signedById });
            if (c2 == null) {
                logger.warn(`Signed by certificate missing for ${c.name}`);
            }
        } 
        // let k = this._privateKeys.findOne({ pairId: c.$loki });
        let s: number[] = this._certificates.find({ signedById: c.$loki }).map((r) => r.$loki);
        return { 
            id: c.$loki,
            certType: CertTypes[c.type],
            name: c.subject.CN,
            issuer: c.issuer,
            subject: c.subject,
            validFrom: c.notBefore,
            validTo: c.notAfter,
            serialNumber: c.serialNumber == null? '' : c.serialNumber.match(/.{1,2}/g).join(':'),  // Hacky fix for dud entries in db
            signer: c2? c2.subject.CN : null,
            signerId: c2? c2.$loki : null,
            keyId: c.keyId,
            fingerprint: c.fingerprint,
            fingerprint256: c.fingerprint256,
            signed: s,
            tags: c.tags?? [],
         };
    }

   /**
    * Tries to delete a certificate and breaks all the links it has with other certificates and keys if any.
    * 
    * @param c The row of the certificate to delete
    * @returns A synopsis of the database updates made as a result of this deletion
    */
    private async _tryDeleteCert(c: CertificateRow & LokiObj): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                let filename = this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c));

                if (await exists(filename)) {
                    await unlink(filename);
                }
                else {
                    logger.error(`Could not find file ${filename}`);
                }
                
                let result: OperationResult = {
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
                    await rename(this._getKeysDir(WebServer._getKeyFilenameFromRow(key)), this._getKeysDir(unknownName));
                    key.name = WebServer._getDisplayName(unknownName);
                    this._privateKeys.update(key);
                    result.updated.push({ type: CertTypes.key, id: key.$loki });
                }

                this._certificates.chain().find({ signedById: c.$loki }).update((cert) => {
                    if (c.$loki != cert.$loki) {
                        cert.signedById = null;
                        result.updated.push({ type: cert.type, id: cert.$loki });
                    }
                })

                this._certificates.remove(c);

                resolve(result);
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
     * @returns OperationResultEx2 promise containing updated entries
     */
    private async _tryAddKey(input: { filename: string, pemString?: string, password?: string } | { filename?: string, pemString: string, password?: string }): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                if (!input.pemString) {
                    logger.info(`Trying to add ${path.basename(input.filename)}`);
                    if (!await exists(input.filename)) {
                        reject(new CertError(404, `${path.basename(input.filename)} does not exist`));
                    }
                    input.pemString = await readFile(input.filename, { encoding: 'utf8' });
                }
                let result: OperationResult = {
                    name: '',
                    added: [],
                    updated: [],
                    deleted: [],
                };

                let k: pki.rsa.PrivateKey;
                let msg = pem.decode(input.pemString)[0];
                let encrypted: boolean = false;
                if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                    if (!input.password) {
                        logger.warn(`Encrypted key requires password`); 
                        return reject(new CertError(400, 'Password is required for key ' + (input.filename?? 'no name')));
                    }
                    k = pki.decryptRsaPrivateKey(input.pemString , input.password);
                    encrypted = true;
                }
                else {
                    k = pki.privateKeyFromPem(input.pemString);
                }

                let kRow: PrivateKeyRow = { e: k.e, n: k.n, pairId: null, pairCN: null, name: null, type: CertTypes.key, encrypted: encrypted };
                let keys = this._privateKeys.find();
                let publicKey = pki.setRsaPublicKey(k.n, k.e);

                // See if we already have this key
                for (let i = 0; i < keys.length; i++) {
                    if (WebServer._isIdenticalKey(pki.setRsaPublicKey(keys[i].n, keys[i].e), publicKey)) {
                        reject(new CertError(409, `Key already present: ${keys[i].name}`));
                    }
                }
                
                // See if this is the key pair for a certificate
                let certs = this._certificates.find({ keyId: null });
                let newFile: string;
                let certIndex: number;

                for (certIndex = 0; certIndex < certs.length; certIndex++) {
                    if (WebServer._isKeyPair(await this._pkiCertFromRow(certs[certIndex]), k.n, k.e)) {
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
                let newRecord: PrivateKeyRow & LokiObj = (this._privateKeys.insert(kRow)) as PrivateKeyRow & LokiObj;
                result.added.push({ type: CertTypes.key, id: newRecord.$loki });

                // Update certificate that key pair
                if (certIndex < certs.length) {
                    certs[certIndex].keyId = newRecord.$loki;
                    this._certificates.update(certs[certIndex]);
                    result.updated.push({ type: certs[certIndex].type, id: certs[certIndex].$loki });
                }

                let newName = WebServer._getKeyFilenameFromRow(newRecord);
                await writeFile(this._getKeysDir(newName), input.pemString, { encoding: 'utf8' });
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
        });
    }

    /**
     * Returns enough information about a key to build the summary on the client browser.
     * 
     * @param r The key row from the database
     * @returns A summary of the database row
     */
    private _getKeyBrief(r: PrivateKeyRow & LokiObj): KeyBrief {
        return { 
            id: r.$loki,
            name: r.name,
            certPair: (r.pairId == null)? 'Not present' : r.name.substring(0, r.name.length -4),
            encrypted: r.encrypted,
        }
    }

    /**
     * Deletes a key's pem file and removes it from the database. If this key has a certificate pair that the certificate will be
     * updated to show that it no longer has its key pair in the system.
     * 
     * @param k Key to delete
     * @returns Summary of modifications to the database
     */
    private _tryDeleteKey(k: PrivateKeyRow & LokiObj): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, reject) => {
            try {
                let result: OperationResult = { name: '', added: [], updated: [], deleted: [] };
                let filename = this._getKeysDir(WebServer._getKeyFilenameFromRow(k));

                if (await exists(filename)) {
                    await unlink(filename);
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
                        result.updated.push({type: cert.type, id: cert.$loki })
                    }
                }

                result.deleted.push({ type: CertTypes.key, id: k.$loki });
                this._privateKeys.remove(k);

                resolve(result);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Takes the certificate's pem string and concatenates the parent certificate's pem string 
     * until it reaches the self signed certificate at the top of the chain 
     * 
     * @param c Certificate at the bottom of the certificate chain
     * @returns Certificate chain
     */
    private async _getChain(c: CertificateRow & LokiObj): Promise<string> {
        return new Promise(async (resolve, reject) => {
            try {
                let file: string = '';
                file = await readFile(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), { encoding: 'utf8' });

                while (c.signedById != c.$loki) {
                    if (c.signedById === null) {
                        return reject(new CertError(404, 'Certificate chain is incomplete'));
                    }
                    c = this._certificates.findOne({ $loki: c.signedById });
                    file += await readFile(this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c)), { encoding: 'utf8'});
                }

                resolve(file);
            }
            catch (err) {
                reject(new CertError(500, err.message));
            }
        });
    }

    /**
     * Takes a filename of a certificate and returns the fully qualified name
     * 
     * @param filename The filename of the certificate
     * @returns The fully qualified name of that certificate
     */
    private _getCertificatesDir(filename: string): string {
        return path.join(this._certificatesPath, filename);
    }

    /**
     * Takes a filename of a key and returns the fully qualified name
     * 
     * @param filename The filename of the key 
     * @returns The fully qualifed name
     */
    private _getKeysDir(filename: string): string {
        return path.join(this._privatekeysPath, filename);
    }

    /**
     * Search for a certificate that signed this certificate
     * @param certificate Certificate for which to search for a signer
     * @returns The certificate row of the certificate that signed the passed certificate
     */
    private async _findSigner(certificate: pki.Certificate): Promise<CertificateRow & LokiObj> {
        return new Promise<CertificateRow & LokiObj>(async(resolve, _reject) => {
            let i;
            let caList = this._certificates.find({ 'type': { '$in': [ CertTypes.root, CertTypes.intermediate ] }});
            for (i = 0; i < caList.length; i++) {
                try {
                    let c = await this._pkiCertFromRow((caList[i]));
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
        });
    }

    /**
     * Find and update any certificates that were signed by the passed certificate
     * 
     * @param certificate Certificate used to test all certificates to see if they were signed by this one
     * @param id The row id from the database
     * @returns The results of the modifications to the certificate rows
     */
    private async _findSigned(certificate: pki.Certificate, id: number): Promise<OperationResultItem[]> {
        return new Promise<OperationResultItem[]>(async (resolve, reject) => {
            let signeeList = this._certificates.find({ $and: [
                { signedById: { $eq: null } }, 
                { $loki: { $ne: id } },
                { type: {  $in: [ CertTypes.leaf, CertTypes.intermediate ] }}
            ]});
            let retVal: OperationResultItem[] = [];
            try {
                for (const s of signeeList) {
                    let check = await this._pkiCertFromRow(s);
                    logger.debug(`Checking ${check.subject.getField('CN').value }`);
                    try {
                        if (certificate.verify(check)) {
                            this._certificates.chain().find({ $loki: s.$loki }).update((u) => {
                                u.signedById = id;
                            });
                            logger.debug(`Marked ${s.name} as signed by ${certificate.subject.getField('CN').name}`);
                            retVal.push({ type: s.type, id: s.$loki });
                        }
                        else {
                            logger.debug(`Did not sign ${check.subject.getField('CN').value }`);
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
        });
    }

    /**
     * Broadcasts the updates to the certificates and keys to all of the web clients
     * 
     * @param data the collection of operation results
     */
    private _broadcast(data: OperationResult): void {
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
    private _resolveCertificateQuery(query: QueryType): CertificateRow & LokiObj {
        let c: (CertificateRow & LokiObj)[];

        if ('name' in query && 'id' in query) throw new CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query)) throw new CertError(400, 'Name or id must be specified');
        
        let selector = ('name' in query)? { name: query.name as string } : { $loki: parseInt(query.id as string)};

        c = this._certificates.find(selector);

        if (c.length == 0) {
            throw new CertError(404, `No certificate for ${JSON.stringify(query)} found`);
        }
        else if (c.length > 1) {
            throw new CertError(400, `Multiple certificates match the CN ${JSON.stringify(query)} - use id instead`);
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
    private _resolveCertificateUpdate(query: QueryType, updater: (row: CertificateRow & LokiObj) => void): OperationResult {
        if ('name' in query && 'id' in query) throw new CertError(422, 'Name and id are mutually exclusive');
        if (!('name' in query) && !('id' in query)) throw new CertError(400, 'Name or id must be specified');
        let selector = ('name' in query)? { name: query.name as string } : { $loki: parseInt(query.id as string)};

        let c = this._certificates.chain().find(selector);

        if (c.count() == 0) {
            throw new CertError(404, `No certificate for ${JSON.stringify(query)} found`);
        }
        else if (c.count() > 1) {
            throw new CertError(400, `Multiple certificates match the CN ${JSON.stringify(query)} - use id instead`);
        }

        let result: OperationResult = { name: null, added: [], updated: [], deleted: [] };
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
    private _resolveKeyQuery(query: QueryType): PrivateKeyRow & LokiObj {
        let k: (PrivateKeyRow & LokiObj)[];
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

        k = this._privateKeys.find(selector);

        if (k.length == 0) {
            throw new CertError(404, `No key for ${JSON.stringify(query)} found`);
        }
        else if (k.length > 1) {
            throw new CertError(400, `Multiple keys match the CN ${JSON.stringify(query)} - use id instead`);
        }

        return k[0];
    }

    /**
     * Returns the decoded pem file referenced by the certificate row
     * 
     * @param c Certificate row
     * @returns A pki.Certificate constructed from the certificate's pem file
     */
    private async _pkiCertFromRow(c: CertificateRow & LokiObj): Promise<pki.Certificate> {
        return new Promise<pki.Certificate>(async (resolve, reject) => {
            try {
                let filename = this._getCertificatesDir(WebServer._getCertificateFilenameFromRow(c));
                resolve(pki.certificateFromPem(await readFile(filename, { encoding: 'utf8' })));
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Returns the decoded pem file referenced by the key row
     * 
     * @param k Key row
     * @param password Optional password if the key is encrypted
     * @returns A pki.PrivateKey constructed from the key's pem file
     */
    private async _pkiKeyFromRow(k: PrivateKeyRow & LokiObj, password?: string): Promise<pki.PrivateKey> {
        return new Promise<pki.PrivateKey>(async (resolve, reject) => {
            try {
                let filename = this._getKeysDir(WebServer._getKeyFilenameFromRow(k));
                let p = await readFile(filename, { encoding: 'utf8' });
                let msg = pem.decode(p)[0];
                if(msg.type.startsWith('ENCRYPTED')) {
                    if (password) {
                        resolve(pki.decryptRsaPrivateKey(p, password));
                    }
                    else {
                        throw new CertError(400, 'No password provided for encrypted key');
                    }
                }
                else {
                    resolve(pki.privateKeyFromPem(p));
                }
            }
            catch (err) {
                reject(err);
            }
        });
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
        // Check that the database is an older version that needs to be modified
        logger.info('Database is a supported version for this release');
    }

    /**
     * Attempts to guess the client OS from the user agent string
     * 
     * @param userAgent User agent string
     * @returns The enum of the OS it thinks is on the client
     */
    private static _guessOs(userAgent: string): userAgentOS {

        if (userAgent === null || userAgent === '') return userAgentOS.UNKNOWN;

        let ua = userAgent.toLowerCase();

        if (ua.includes('windows')) return userAgentOS.WINDOWS;
        if (ua.includes('linux')) return userAgentOS.LINUX;
        if (ua.includes('curl')) return userAgentOS.LINUX;           // Best guess
        if (ua.includes('mac')) return userAgentOS.MAC;
        if (ua.includes('x11')) return userAgentOS.LINUX;
        if (ua.includes('iphone')) return userAgentOS.IPHONE;
        if (ua.includes('android')) return userAgentOS.ANDROID;
        return userAgentOS.UNKNOWN;
    }

    private static _isValidRNASequence(rnas: string[]): { valid: boolean, message?: string } {
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
    private static _isKeyPair(cert: pki.Certificate, keyn: jsbn.BigInteger, keye: jsbn.BigInteger): boolean {
        let publicKey = pki.setRsaPublicKey(keyn, keye);
        let certPublicKey: pki.rsa.PublicKey = cert.publicKey as pki.rsa.PublicKey;

        return this._isIdenticalKey(publicKey, certPublicKey);
    }

    /**
     * Compares to keys for equality
     * 
     * @param leftKey First key to compare
     * @param rightKey Second key to compare
     * @returns true if the keys are identical
     */
    private static _isIdenticalKey(leftKey: pki.rsa.PublicKey, rightKey: pki.rsa.PublicKey): boolean {
        if (leftKey.n.data.length != rightKey.n.data.length) {
            return false;
        }

        for (let i = 0; i < leftKey.n.data.length; i++) {
            if (leftKey.n.data[i] != rightKey.n.data[i]) return false;
        }

        return true;
    }

    /**
     * Determines the filename of a certificate from the database record
     * 
     * @param c Certificate's database record
     * @returns Filename in the form of name_identity.pem
     */
    private static _getCertificateFilenameFromRow(c: CertificateRow & LokiObj): string {
        return `${c.name}_${c.$loki}.pem`;
    }

    /**
     * Determines the filename of a key from the database record
     * 
     * @param k key's database record
     * @returns Filename in the form of name_identity.pem
     */
    private static _getKeyFilenameFromRow(k: PrivateKeyRow & LokiObj): string {
        return WebServer._getKeyFilename(k.name, k.$loki);
    }

    /**
     * Determines the filename for a key
     * 
     * @param name Name in the key record
     * @param $loki Identity in the key record
     * @returns Filename in the form of name_identity.pem
     */
    private static _getKeyFilename(name: string, $loki: number): string {
        return `${name}_${$loki}.pem`;
    }

    /**
     * Removes the id from the end of the input name
     * 
     * @param name Input name
     * @returns Display name
     */
    private static _getDisplayName(name: string): string {
        return name.split('_').slice(0, -1).join('_');
    }

    /**
     * Parse the id from the end of the filename
     * 
     * @param name Filename of key or certificate
     * @returns  Database id associated with this file
     */
    private static _getIdFromFileName(name: string): number {
        return parseInt(path.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }

    /**
     * Converts certain special characters to an underscore
     * 
     * @param name Input string
     * @returns Input with special characters replaced with underscores
     */
    private static _sanitizeName(name: string): string {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }

    /**
     * Extracts the issuer or subject values and returns them as a CertificateSubject
     * 
     * @param s pki.Certificate field
     * @returns Extracted subject elements
     */
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

    /**
     * Add subject values to pki.CertificateField
     * 
     * @param subject Subject fields for the certificate
     * @returns pki.CertificateField with the provided fields
     */
    private static _setAttributes(subject: CertificateSubject): pki.CertificateField[] {
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

    /**
     * Generates a certificate serial number
     * 
     * @returns A random number to use as a certificate serial number
     */
    private static  _getRandomSerialNumber(): string {
        return WebServer._makeNumberPositive(util.bytesToHex(random.getBytesSync(20)));
    }

    /**
     * If the passed number is negative it is made positive
     * 
     * @param hexString String containing a hexadecimal number
     * @returns Positive version of the input
     */
    private static _makeNumberPositive = (hexString: string): string => {
        let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);

        if (mostSignificativeHexDigitAsInt < 8)
            return hexString;

        mostSignificativeHexDigitAsInt -= 8;
        return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
    };
}

