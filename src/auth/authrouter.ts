import http from 'http';
import { Request, Response, NextFunction, Router } from 'express';
import { JsonWebTokenError, JwtPayload, decode, sign, verify } from 'jsonwebtoken';
import * as crypto from 'crypto';
import * as log4js from 'log4js';

import { UserStore } from '../database/userStore';
import { CertError } from '../webservertypes/CertError';
import { CertMultiError } from '../webservertypes/CertMultiError';
import { UserRole } from '../database/UserRole';
import { DbStores } from '../database/dbStores';
import { WSManager } from '../wsmanger/wsmanager';

const logger = log4js.getLogger('CertServer');
const tokenLife: string | number = '5m';
const defaultUser: string = 'admin';
const defaultPassword: string = 'changeme';

/**
 * @classdesc Represents a router for handling authentication-related routes.
 */
export class AuthRouter {
    private _authRouter = Router();
    private _authRouterAPI = Router();
    private _passwordSecret: string = DbStores.getPasswordSecret();
    private _authPtr: (request: Request, response: Response, next: NextFunction) => void = this._noAuth;
    private _checkAuthPtr: (request: Request, response: Response, next: NextFunction) => void = this._noAuth;
    private _authRequired: boolean = false;
    private _allowBasicAuth: boolean = false;
    private _allowDigestAuth: boolean = false;

    /**
     * @constructor
     * @param authRequired - Will be true if authentication is required, false otherwise.
     */
    constructor(authRequired: boolean, allowBasicAuth: boolean, allowDigestAuth: boolean) {
        this._authRequired = authRequired;
        this._allowBasicAuth = allowBasicAuth;
        this._allowDigestAuth = allowDigestAuth;
        if (this._authRequired) {
            this._authPtr = this._auth;
            this._checkAuthPtr = this._checkAuth;

            if (UserStore.getUsersByRole(UserRole.ADMIN).length == 0) {
                logger.warn('No admin users found - adding default admin user');
                UserStore.addUser(defaultUser, defaultPassword, UserRole.ADMIN);
            }
        }
        this._authRouter.get('/signin', (_request, response) => {
            if (!this._authRequired) {
                return response.redirect('/');
            }
            response.render('signin', {
                title: 'Sign In',
                version: 'v' + require('../../../package.json').version,
                authRequired: `${authRequired ? '1' : '0'}`,
            });
        });
        this._authRouter.get('/signout', (request, response) => {
            request.session.userId = '';
            request.session.role = null;
            request.session.token = '';
            request.session.lastSignedIn = null;
            request.session.tokenExpiration = null;
            response.redirect('/signin');
        });
        this._authRouterAPI.post('/login', async (request, response) => {
            try {
                const { userId, password } = request.body;
                logger.debug(`Login request - User: ${userId}`);
                let role = UserStore.authenticate(userId, password);
                let { token, expiresAt } = await this.generateToken({ userId: userId, role: role }, this._passwordSecret, (request.query.ttl as string) ?? tokenLife);
                request.session.userId = userId;
                request.session.role = role;
                request.session.token = token;
                request.session.lastSignedIn = new Date();
                request.session.tokenExpiration = expiresAt;
                logger.debug('Login successful');
                return response.status(200).json({ success: true, token: token, userId: userId, role: role, expiresAt: expiresAt });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.post('/tokenrefresh', this.auth, async (request, response) => {
            try {
                if (!request.session.token) {
                    throw new CertError(403, 'You must be logged in to refresh a token');
                }
                let { token, expiresAt } = await this.generateToken({ userId: request.session.userId, role: request.session.role }, this._passwordSecret, tokenLife);
                request.session.token = token;
                request.session.tokenExpiration = expiresAt;
                logger.debug('Token refresh successful');
                return response.status(200).json({ success: true, token: token, expiresAt: expiresAt });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.post('/token', this.auth, async (request, response) => {
            try {
                // Returns a shortlived token to be used for a WebSockets connection
                if (!request.session.token) {
                    throw new CertError(403, 'You must be logged in to get a temporary token');
                }
                let decoded = await this.verifyToken(request.session.token, this._passwordSecret);
                logger.debug(decoded)
                if ((decoded as JwtPayload).userId != request.session.userId) {
                    throw new CertError(403, 'You can only get a token for your own session');
                }
                let { userId, role } = decoded as any;
                let token = await this.generateToken({ userId: userId, role: role }, this._passwordSecret, 5);
                logger.debug('Temporary token creation successful');
                return response.status(200).json({ success: true, token: token.token });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.get('/authrequired', (_request, response) => {
            response.status(200).json({ authRequired: this._authRequired });
        });
        this._authRouterAPI.get('/getUsers', this.auth, (request, response) => {
            try {
                let users = UserStore.getAllUsers();
                if (request.session.role != UserRole.ADMIN) {
                    users = users.filter((u) => u.username == request.session.userId);
                }
                if (users.length == 0) {
                    throw new CertError(500, 'No users found - internal error');
                }
                logger.debug('Get users successful');
                // TODO: fix up database so all users have a role
                return response.status(200).json(users
                    .map((u) => { return { username: u.username, role: u.role === undefined? UserRole.USER : u.role, id: u.$loki } })
                    .sort((a, b) => a.username.localeCompare(b.username)));
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.get('/getUser', this.auth, (request, response) => {
            try {
                let user = UserStore.getUser(Number(request.query.id));
                if (!user) {
                    throw new CertError(404, 'User not found');
                }
                logger.debug('Get user successful');
                return response.status(200).json({ username: user.username, role: user.role, id: user.$loki });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.post('/addUser', this.auth, (request, response) => {
            try {
                if (request.session.role != UserRole.ADMIN) {
                    throw new CertError(403, 'You must be an admin to add a user');
                }
                const { username, password, confirmpassword, role } = request.body;
                if (password != confirmpassword) {
                    throw new CertError(400, 'Passwords do not match');
                }
                if (UserStore.getUser(username)) {
                    throw new CertError(400, `User ${username} already exists`);
                }
                let result = UserStore.addUser(username, password, role == '0'? UserRole.ADMIN : UserRole.USER);
                logger.debug(`User ${username} added successfully`);
                WSManager.broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.post('/updateUser', this.auth, (request, response) => {
            try {
                const { userpassword, userid, username, newpassword, confirmpassword } = request.body;
                if (username != request.session.userId && request.session.role != UserRole.ADMIN) {
                    throw new CertError(403, 'You must be an admin to update a user');
                }
                if (newpassword != confirmpassword) {
                    throw new CertError(400, 'Passwords do not match');
                }
                if (userid == request.session.userId) {
                    UserStore.authenticate(username, userpassword);
                }
                let result = UserStore.updatePassword(userid, newpassword);
                logger.debug(`User ${result.name} updated successfully`);
                WSManager.broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouterAPI.delete('/removeUser', this.auth, (request, response) => {
            try {
                if (request.session.role != UserRole.ADMIN) {
                    throw new CertError(403, 'You must be an admin to remove a user');
                }
                const userId = Number(request.query.id);
                let result = UserStore.removeUser(userId);
                logger.debug(`User ${userId} removed successfully`);
                WSManager.broadcast(result);
                return response.status(200).json(result.getResponse());
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
    }

    /**
     * Gets the router for handling authentication routes.
     * @returns The authentication router.
     */
    public get router(): Router {
        return this._authRouter;
    }

    /**
     * Gets the API router for authentication.
     * @returns The API router for authentication.
     */
    public get routerAPI(): Router {
        return this._authRouterAPI;
    }

    /**
     * Authenticates a request to open a WebSocket connection.
     * @param request - The incoming HTTP request.
     * @param socket - The socket connection.
     * @throws {CertError} - If the token is not provided or the user does not exist.
     */
    public socketUpgrade(request: http.IncomingMessage, socket: any) {
        let token: string = null;
        if (this._authRequired) {
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
            let decoded = verify(token, this._passwordSecret);
            logger.debug(decoded);
            if (!UserStore.getUser((decoded as any).userId)) {
                socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                socket.end();
                throw new CertError(401, `User ${(decoded as any).userId} not found`);
            }
        }
    }

    /**
     * Returns the authentication middleware function.
     * @returns The authentication middleware function.
     */
    public get auth(): (request: Request, response: Response, next: NextFunction) => void {
        return this._authPtr.bind(this);
    }

    /**
     * Returns the middleware function for checking authentication.
     * @returns A middleware function that checks authentication.
     */
    public get checkAuth(): (request: Request, response: Response, next: NextFunction) => void {
        return this._checkAuthPtr.bind(this);
    }

    /**
     * Middleware function that allows the request to proceed without authentication.
     * @param _request - The request object.
     * @param _response - The response object.
     * @param next - The next function to call in the middleware chain.
     */
    private _noAuth(_request: Request, response: Response, next: NextFunction): void {
        try {
            if (!this._authRequired) {
                throw new CertError(400, 'Authentication is not enabled');
            }
            next();
        }
        catch(err: any) {
            logger.error(err.message);
            let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
            response.status(e.status).json(e.getResponse());
        }
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
    private _checkAuth(request: Request, response: Response, next: NextFunction): void {
        try {
            if (this._authRequired) {
                if (request.session.userId == '' || !request.session.token) {
                    return response.redirect('/signin');
                }
                let decoded = verify(request.session.token, this._passwordSecret);
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
            response.redirect('/signin');
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
    private _auth(request: Request, response: Response, next: NextFunction): void {
        try {
            if (this._passwordSecret) {
                let token: string = null;
                if (request.headers.authorization) {
                    let authType = request.headers.authorization.split(' ');
                    switch (authType[0]) {
                        case 'Basic':
                            if (!this._allowBasicAuth) {
                                throw new CertError(403, 'Basic auth not allowed');
                            }
                            let auth = Buffer.from(request.headers.authorization.split(' ')[1], 'base64').toString().split(':');
                            let role = UserStore.authenticate(auth[0], auth[1]);
                            logger.debug(`Bearer auth successful for ${auth[0]} role ${role}`);
                            next();
                            return;
                        case 'Digest':
                            if (!this._allowDigestAuth) {
                                throw new CertError(403, 'Digest auth not allowed');
                            }
                            logger.warn('Digest auth not implemented');
                            break;
                            // throw new CertError(403, 'Digest auth not implemented');
                            // return;
                        case 'Bearer':
                            token = authType[1];
                            break;
                        default:
                            throw new CertError(403, 'Invalid authorization type');
                    }
                }
                else if (request.session.token) {
                    token = request.session.token;
                }
                else {
                    throw new CertError(403, 'No authorization provided');
                }
                let decoded = verify(token, this._passwordSecret);
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
            // if (e.status == 401) {
            //     response.appendHeader('WWW-Authenticate', `Digest realm="CertServer", qop="auth,auth-int", nonce="${crypto.randomBytes(16).toString('base64')}", opaque="${crypto.randomBytes(16).toString('base64')}"`);
            // }
            response.status(e.status).json(e.getResponse());
        }
    }

    /**
     * Verifies the given token using the provided secret.
     * @param token - The token to be verified.
     * @param secret - The secret used for verification.
     * @returns A Promise that resolves to the decoded token payload if verification is successful, or rejects with an error if verification fails.
     */
    private async verifyToken(token: string, secret: string): Promise<string | JwtPayload> {
        return new Promise<string | JwtPayload>((resolve, reject) => {
            verify(token, secret, (err, decoded) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(decoded);
                }
            });
        });
    }

    /**
     * Generates a token for the specified user ID.
     * @param userId - The ID of the user.
     * @param secret - The secret key used to sign the token.
     * @param expires - The expiration time of the token, in seconds or a string describing a time span.
     * @returns A promise that resolves to an object containing the generated token and its expiration timestamp.
     */
    private async generateToken(toSign: object, secret: string, expires: number | string): Promise<{ token: string, expiresAt: number }> {
        return new Promise<{ token: string, expiresAt: number }>((resolve, reject) => {
            sign(toSign, secret, { expiresIn: expires }, (err, token) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve({ token: token, expiresAt: (decode(token) as JwtPayload).exp });
                }
            });
        });
    }
}

