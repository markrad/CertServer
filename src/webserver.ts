import { existsSync, mkdirSync } from 'node:fs';
import path from 'path';
import http from 'http';
import https from 'https';
import fs from 'fs';
import { readFile } from 'fs/promises'

import { /* pki, */ pem, /* util, random, md */ } from 'node-forge'; 
import loki, { Collection, LokiFsAdapter } from 'lokijs'
import Express, { NextFunction, /*Request, /* response */ } from 'express';
import FileUpload from 'express-fileupload';
import serveFavicon from 'serve-favicon';
import session from 'express-session'
// declare global {
//     namespace Express {
//         interface Session {
//             userId: string;
//             password: string;
//         }
//     }
// }
// export interface Request extends Express.Request {
//     session: Express.Session;
// }
// interface Session {
//     userId: string;
//     password: string;
// }
// interface Request {
//     session: Session;
// }


import WsServer from 'ws';
import { Readable } from 'stream';
import * as log4js from 'log4js';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

import { EventWaiter } from './utility/eventWaiter';
import { exists } from './utility/exists';
import { OperationResult, ResultType } from './webservertypes/OperationResult';
import { CertTypes } from './webservertypes/CertTypes';
import { Config } from './webservertypes/Config';
import { CertificateRow } from './database/CertificateRow';
import { PrivateKeyRow } from './database/PrivateKeyRow';
import { DBVersionRow } from './database/DBVersionRow';
import { CertificateLine } from './webservertypes/CertificateLine';
import { CertificateBrief } from './webservertypes/CertificateBrief';
import { KeyBrief } from './webservertypes/KeyBrief';
import { QueryType } from './webservertypes/QueryType';
import { userAgentOS } from './webservertypes/userAgentOS';
import { CertError } from './webservertypes/CertError';
import { CertMultiError } from "./webservertypes/CertMultiError";
import { KeyLine } from './webservertypes/KeyLine';
import { KeyStores } from './database/keyStores';
import { KeyUtil } from './database/keyUtil';
import { CertificateStores } from './database/certificateStores';
import { CertificateUtil } from './database/certificateUtil';
import { OperationResultItem } from './webservertypes/OperationResultItem';
import { DbStores } from './database/dbStores';
import { DB_NAME } from './database/dbName';
import { UserStore } from './database/userStore';
import { UserRow } from './database/UserRow';
import { KeyEncryption } from './database/keyEncryption';

const logger = log4js.getLogger('CertServer');
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
    private _hashSecret: string = null;
    private _keySecret: string = null;
    private _config: Config;
    private _version = 'v' + require('../../package.json').version;
    private static readonly _lowestDBVersion: number = 4;           // The lowest version of the database that is supported
    public static readonly _defaultDBVersion: number = 5;           // The version of the database that will be created if it doesn't exist
    private _currentVersion: number = 0;
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

        if (config.certServer.hashSecret) {
            if (!config.certServer.certificate) {
                throw new Error('Hash secret requires TLS encryption to be enabled');
            }

            this._hashSecret = config.certServer.hashSecret;
        }

        if (config.certServer.keySecret) {
            if (!config.certServer.certificate) {
                throw new Error('Key secret requires TLS encryption to be enabled');
            }

            this._keySecret = config.certServer.keySecret;
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
        logger.info(`Data path: ${this._dataPath}`);
        logger.info(`TLS enabled: ${this._certificate != null}`);
        logger.info(`Authentication enabled: ${this._hashSecret != null}`);
        logger.info(`Key encryption enabled: ${this._keySecret != null}`);
        let getCollections: () => void = function() {
            if (null == (certificates = db.getCollection<CertificateRow>('certificates'))) {
                certificates = db.addCollection<CertificateRow>('certificates', { });
            }
            if (null == (privateKeys = db.getCollection<PrivateKeyRow>('privateKeys'))) {
                privateKeys = db.addCollection<PrivateKeyRow>('privateKeys', { });
            }
            if (null == (dbVersion = db.getCollection<DBVersionRow>('dbversion'))) {
                dbVersion = db.addCollection<DBVersionRow>('dbversion', { });
            }
            if (null == (userStore = db.getCollection<UserRow>('users'))) {
                userStore = db.addCollection<UserRow>('users', { });
            }

            ew.EventSet();
        }

        try {
            var ew = new EventWaiter();
            var certificates: Collection<CertificateRow> = null;
            var privateKeys: Collection<PrivateKeyRow> = null;
            var dbVersion: Collection<DBVersionRow> = null;
            var userStore: Collection<UserRow> = null;
            var db = new loki(path.join(this._dbPath.toString(), DB_NAME), { 
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

            CertificateStores.init(certificates, path.join(this._dataPath, 'certificates'));
            KeyStores.init(privateKeys, path.join(this._dataPath, 'privatekeys'), this._keySecret);
            DbStores.init(dbVersion);
            UserStore.init(userStore);

            await this._dbInit();
        }
        catch (err) {
            logger.fatal('Failed to initialize the database: ' + err.message);
            process.exit(4);
        }

        /**
         * Middleware function to check authentication before processing the request.
         * If the user is not authenticated, it redirects to the signin page.
         * If the user is authenticated, it verifies the session token and checks if the user exists.
         * If authentication fails, it logs a warning and redirects to the signin page.
         *
         * @param request - The HTTP request object.
         * @param response - The HTTP response object.
         * @param next - The next function to be called in the middleware chain.
         */
        let checkAuth = (request: any, response: any, next: NextFunction) => {
            try {
                if (this._hashSecret) {
                    if (request.session.userId == '' || !request.session.token) {
                        return response.redirect('/signin');
                    }
                    let decoded = jwt.verify(request.session.token, this._hashSecret);
                    logger.debug(decoded);
                    if (!UserStore.getUser((decoded as any).userId)) {
                        throw new CertError(401, `User ${(decoded as any).userId} not found`);
                    }
                }
                next();
            }
            catch (err) {
                // TODO - Pass error message to sign in page
                logger.warn(`Failed to authenticate: ${err.message}`);
                // let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                // return response.status(e.status).json(e.getResponse());
                return response.redirect('/signin');
            }
        }

        /**
         * Middleware function for authentication.
         * Verifies the token provided in the request headers and checks if the user exists.
         * If the token is expired, it redirects to the sign-in page.
         * If there is an error during authentication, it returns the appropriate error response.
         * @param request - The HTTP request object.
         * @param response - The HTTP response object.
         * @param next - The next function to be called in the middleware chain.
         */
        let auth = (request: any, response: any, next: NextFunction) => {
            try {
                if (this._hashSecret) {
                    let token: string = null;
                    if (request.headers.authorization) {
                        token = request.headers.authorization.split(' ')[1];
                    }
                    else if (request.session.token) {
                        token = request.session.token;
                    }
                    else {
                        throw new CertError(401, 'No token provided');
                    } 
                    let decoded = jwt.verify(token, this._hashSecret);
                    logger.debug(decoded);
                    if (!UserStore.getUser((decoded as any).userId)) {
                        throw new CertError(401, `User ${(decoded as any).userId} not found`);
                    }
                }
                next();
            }
            catch (err) {
                logger.warn(err.message);
                let e: (CertError | CertMultiError);
                if (err instanceof JsonWebTokenError) {
                    e = new CertError(401, err.message);
                }
                else {
                    e = CertMultiError.getCertError(err);
                }
                return response.status(e.status).json(e.getResponse());
            }
        }
        let verifyToken = async (token: string, secret: string) => {
            return new Promise<string | jwt.JwtPayload>((resolve, reject) => {
                jwt.verify(token, secret, (err, decoded) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(decoded);
                    }
                });
            });
        }

        this._app.use(Express.urlencoded({ extended: true }));
        this._app.use(serveFavicon(path.join(__dirname, "../../web/icons/doc_lock.ico"), { maxAge: 2592000000 }));
        this._app.use(Express.json({ type: '*/json' }));
        this._app.use(Express.text({ type: 'text/plain' }));
        this._app.use(Express.text({ type: 'application/x-www-form-urlencoded' }));
        this._app.use(Express.text({ type: 'application/json' }));this._app.use('/scripts', Express.static(path.join(__dirname, '../../web/scripts')));
        this._app.use('/styles', Express.static(path.join(__dirname, '../../web/styles')));
        this._app.use('/icons', Express.static(path.join(__dirname, '../../web/icons')));
        this._app.use('/files', Express.static(path.join(__dirname, '../../web/files')));
        this._app.use('/images', Express.static(path.join(__dirname, '../../web/images')));
        this._app.use(FileUpload());
        this._app.use(session({
            secret: 'mysecret',
            name: 'certserver',
            resave: false,
            saveUninitialized: false
        }));
        this._app.use((request: any, response: any, next: NextFunction) => {
            if (!request.session.userId) {
                request.session.userId = '';
                request.session.lastSignedIn = null;
                request.session.tokenExpiration = null;
                request.session.token = null;
            }
            const redirects: { [key: string]: string } = {
                '/api/uploadCert':          '/api/uploadPem',
                '/api/helpers':             '/api/helper',
                '/api/script':              '/api/helper',
                '/createCACert':            '/api/createCACert',
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
                '/login':                   '/api/login'
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
        this._app.get('/', checkAuth, (_request, response) => {
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
        this._app.get('/signin', (_request, response) => {
            response.render('signin', { 
                title: 'Sign In',
                version: this._version,
            });
        });
        // FUTURE: Add a signout route?
        this._app.post('/api/login', (request: any, response) => {
            try {
                const { userId, password } = request.body;
                logger.debug(`Login request - User: ${userId}`);
                if (UserStore.authenticate(userId, password)) {
                    let token = jwt.sign({ userId: userId }, this._hashSecret, {expiresIn: '1h' });
                    // TODO - Does not handle multiple signins
                    request.session.userId = userId;
                    request.session.token = token;
                    request.session.lastSignedIn = new Date();
                    request.session.tokenExpiration = new Date(Date.now() + 3600000);
                    logger.debug('Login successful');
                    return response.status(200).json({ success: true, token: token });
                }
                else {
                    throw new CertError(401,'Invalid credentials');
                }
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.post('/api/token', auth, async (request: any, response: any) => {
            try {
                if (!request.session.token) {
                    throw new CertError(401, 'You must be logged in to get a temporary token');
                }
                // const { userId } = request.body;
                // if (userId != request.session.userId) {
                //     throw new CertError(401, 'You can only get a token for your own session');
                // }
                let decoded = await verifyToken(request.session.token, this._hashSecret);
                logger.debug(decoded)
                if ((decoded as any).userId != request.session.userId) {
                    throw new CertError(401, 'You can only get a token for your own session');
                }
                let token = jwt.sign({ userId: 'aa' }, this._hashSecret, { expiresIn: 5 });
                logger.debug('Temporary token creation successful');
                return response.status(200).json({ success: true, token: token });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
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
                        `export AUTH_REQUIRED=${Number(this._hashSecret != null).toString()}\n`,
                    ].concat(((await readFile('src/files/linuxhelperscript.sh', { encoding: 'utf8' })).split('\n').map((l) => l + '\n'))));
                }
                else if (os == userAgentOS.WINDOWS) {
                    response.setHeader('content-disposition', `attachment; filename="${request.hostname}-${this._port}.ps1"`);
                    readable = Readable.from([
                        `Set-Item "env:CERTSERVER_HOST" -Value "${hostname}"\n`,
                        `Set-Item "env:REQUEST_PATH" -Value "${request.path}"\n`,
                        `Set-Item "env:AUTH_REQUIRED" -Value "${Number(this._hashSecret != null).toString()}"\n`,
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
        this._app.get('/api/authrequired', (_request: any, response: any) => {
            response.status(200).json({ authRequired: this._hashSecret != null });
        });
        this._app.post('/updateCertTag', auth, async (request, _response, next) => {
            request.url = '/api/updateCertTag';
            request.query['id'] = request.body.toTag;
            next();
        });
        this._app.post(/\/api\/create.*Cert/i, auth, async (request, response) => {
            try {
                logger.debug(request.body);
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
                        messages: [{ type: 0, message: `Certificate/Key ${certResult.name}/${keyResult.name} added` }], 
                        newIds: { certificateId: certId, keyId: keyId } 
                    });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/certName', auth, async(request, response) => {
            try {
                let c = this._resolveCertificateQuery(request.query as QueryType);
                return response.status(200).json({ name: c.subject.CN, id: c.$loki, tags: c.tags?? [] });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.get('/api/certDetails', auth, async (request, response) => {
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
        this._app.get('/api/keyList', auth, (request, _response, next) => {
            request.url = '/api/certList';
            request.query = { type: 'key' };
            next();
        });
        this._app.get('/api/keyDetails', auth, async (request, response) => {
        
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
        this._app.get('/api/certList', auth, (request, response) => {
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
        this._app.get('/api/getCertificatePem', auth, async (request, response) => {
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
        this._app.delete('/api/deleteCert', auth, async (request, response) => {
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
        this._app.post('/api/updateCertTag', auth, async (request, response) => {
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
        this._app.get('/api/keyname', auth, async(request, response) => {
            try {
                let k = this._resolveKeyQuery(request.query as QueryType);
                response.status(200).json({ name: k.name, id: k.$loki, tags: [] });
            }
            catch (err) {
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._app.delete('/api/deleteKey', auth, async (request, response) => {
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
        this._app.get('/api/getKeyPem', auth, async (request, response) => {

            try {
                let k: KeyUtil = this._resolveKeyQuery(request.query as QueryType);
                response.setHeader('content-disposition', `attachment; filename="${k.name}.pem"`);
                let readable = Readable.from([await k.getPemString()]);
                readable.pipe(response);
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
        this._app.post('/uploadPem', auth, (async (request: any, response) => {
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
        this._app.post('/api/uploadPem', auth, async (request, response) => {
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
        this._app.get('/api/ChainDownload', auth, async (request, response) => {
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
                logger.info(`Listening on ${this._port} with TLS enabled`);
            }
            else {
                server = http.createServer(this._app).listen(this._port, '0.0.0.0');
                logger.info(`Listening on ${this._port}`);
            }
        }
        catch (err) {
            logger.fatal(`Failed to start webserver: ${err}`);
        }

        server.on('error', (err) => {
            logger.fatal(`Webserver error: ${err.message}`);
            process.exit(4);
        })

        server.on('upgrade', async (request, socket, head) => {
            let token: string = null;
            try {
                if (this._hashSecret) {
                    if (request.url.startsWith('/?token=')) {
                        token = request.url.split('=')[1];
                    }
                    else if (request.headers['authorization'] != null) {
                        token = request.headers['authorization'].split(' ')[1];
                    }
                    else {
                        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                        socket.end();
                        throw new CertError(401, 'No token provided');
                    }
                    let decoded = jwt.verify(token, this._hashSecret);
                    logger.debug(decoded);
                    if (!UserStore.getUser((decoded as any).userId)) {
                        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                        socket.end();
                        throw new CertError(401, `User ${(decoded as any).userId} not found`);
                    }
                }
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
                    this._currentVersion = WebServer._defaultDBVersion;
                    DbStores.updateVersion(this._currentVersion);
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

                files = fs.readdirSync(CertificateStores.certificatePath);

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
                            adding.push(this._tryAddKey({ filename: path.join(this._privatekeysPath, file), password: this._keySecret }));
                        }
                        catch (err) {
                            logger.debug('WTF');
                        }
                    }
                });

                await Promise.allSettled(adding);

                this._db.saveDatabase((err) => {
                    if (err) reject(err);
                });

                await this._databaseFixUp();
                await this._keySecretFixUp();
                resolve();
            }
            catch (err) {
                reject(err);
            }
        });
    }

    private async _keySecretFixUp(): Promise<void> {
        const currentKeySecret = DbStores.getKeySecret();
        if (this._keySecret != currentKeySecret) {
            if (currentKeySecret == null) {
                logger.info('Key secret has been added - encrypting all keys');
                let keys = KeyStores.find({ encryptedType: { $eq: KeyEncryption.NONE }});
                for (let k of keys) {
                    await k.encrypt(this._keySecret, KeyEncryption.SYSTEM);
                }
                logger.info(`Encrypted ${keys.length} keys`);
            }
            else if (this._keySecret == null) {
                logger.info('Key secret has been removed - decrypting all keys');
                let keys = KeyStores.find({ encryptedType: { $eq: KeyEncryption.SYSTEM }});
                for (let k of keys) {
                    await k.decrypt(currentKeySecret);
                }
                logger.info(`Decrypted ${keys.length} keys`);
            }
            else {
                logger.info('Key secret has been changed - re-encrypting all keys');
                let keys = KeyStores.find({ encryptedType: { $eq: KeyEncryption.SYSTEM }});
                for (let k of keys) {
                    await k.decrypt(this._keySecret);
                    await k.encrypt(currentKeySecret, KeyEncryption.SYSTEM);
                }
            }
            DbStores.updateKeySecret(this._keySecret);
        }
    }

    /**
     * Processes a multi-file PEM string and adds the certificates or keys to the server.
     * @param pemString The multi-file PEM string to process.
     * @returns A promise that resolves to an OperationResult indicating the result of the operation.
     */
    private async _processMultiFile(pemString: string): Promise<OperationResult> {
        return new Promise<OperationResult>(async (resolve, _reject) => {
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

        // Check that the database is an older version that needs to be modified
        logger.info('Database is a supported version for this release');

        // Add the encryption type in preperation for system encryption
        if (this._currentVersion == 4) {
            logger.info(`Updating database to version ${++this._currentVersion}`);
            let keys = KeyStores.find();
            for (let k of keys) {
                k.encryptedType = k.encrypted? KeyEncryption.USER : KeyEncryption.NONE;
                k.update();
            }
            DbStores.updateVersion(this._currentVersion);
            logger.info(`Updated ${keys.length} keys`);
            logger.info(`Database updated to version ${this._currentVersion}`);
        }
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
}

