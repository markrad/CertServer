import http from 'http';
import { NextFunction, Router } from 'express';
import { JsonWebTokenError, JwtPayload, decode, sign, verify } from 'jsonwebtoken';
import * as log4js from 'log4js';

import { UserStore } from '../database/userStore';
import { CertError } from '../webservertypes/CertError';
import { CertMultiError } from '../webservertypes/CertMultiError';

const logger = log4js.getLogger('CertServer');
const tokenLife: string | number = '5m';

/**
 * @classdesc Represents a router for handling authentication-related routes.
 */
export class AuthRouter {
    private _authRouter = Router();
    private _hashSecret: string;
    private _authPtr: (request: any, response: any, next: NextFunction) => void = this._noAuth;
    private _checkAuthPtr: (request: any, response: any, next: NextFunction) => void = this._noAuth;

    /**
     * @constructor
     * @param hashSecret - The secret key used to hash the JWT token. If not provided, the router will not require authentication.
     */
    constructor(hashSecret: string) {
        this._hashSecret = hashSecret;

        if (this._hashSecret) {
            this._authPtr = this._auth;
            this._checkAuthPtr = this._checkAuth;
        }

        this._authRouter.get('/signin', (_request, response) => {
            response.render('signin', {
                title: 'Sign In',
                version: 'v' + require('../../../package.json').version,
            });
        });
        // FUTURE: Add a signout route?
        this._authRouter.post('/login', async (request: any, response) => {
            try {
                const { userId, password } = request.body;
                logger.debug(`Login request - User: ${userId}`);
                let role =UserStore.authenticate(userId, password);
                let { token, expiresAt } = await this.generateToken({ userId: userId, role: role }, this._hashSecret, tokenLife);
                request.session.userId = userId;
                request.session.token = token;
                request.session.lastSignedIn = new Date();
                request.session.tokenExpiration = expiresAt;
                logger.debug('Login successful');
                return response.status(200).json({ success: true, token: token, userId: userId, expiresAt: expiresAt });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouter.post('/tokenrefresh', this.auth, async (request: any, response: any) => {
            try {
                if (!request.session.token) {
                    throw new CertError(401, 'You must be logged in to refresh a token');
                }
                let { token, expiresAt } = await this.generateToken(request.session.userId, this._hashSecret, tokenLife);
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
        this._authRouter.post('/token', this.auth, async (request: any, response: any) => {
            try {
                // Returns a shortlived token to be used for a WebSockets connection
                if (!request.session.token) {
                    throw new CertError(401, 'You must be logged in to get a temporary token');
                }
                let decoded = await this.verifyToken(request.session.token, this._hashSecret);
                logger.debug(decoded)
                if ((decoded as JwtPayload).userId != request.session.userId) {
                    throw new CertError(401, 'You can only get a token for your own session');
                }
                let token = await this.generateToken((decoded as JwtPayload).userId, this._hashSecret, 5);
                logger.debug('Temporary token creation successful');
                return response.status(200).json({ success: true, token: token.token });
            }
            catch (err) {
                logger.error(err.message);
                let e: (CertError | CertMultiError) = CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        });
        this._authRouter.get('/authrequired', (_request: any, response: any) => {
            response.status(200).json({ authRequired: this._hashSecret != null });
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
     * Authenticates a request to open a WebSocket connection.
     * @param request - The incoming HTTP request.
     * @param socket - The socket connection.
     * @throws {CertError} - If the token is not provided or the user does not exist.
     */
    public socketUpgrade(request: http.IncomingMessage, socket: any) {
        let token: string = null;
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
            let decoded = verify(token, this._hashSecret);
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
    public get auth(): (request: any, response: any, next: NextFunction) => void {
        return this._authPtr.bind(this);
    }

    /**
     * Returns the middleware function for checking authentication.
     * @returns A middleware function that checks authentication.
     */
    public get checkAuth(): (request: any, response: any, next: NextFunction) => void {
        return this._checkAuthPtr.bind(this);
    }

    /**
     * Middleware function that allows the request to proceed without authentication.
     * @param _request - The request object.
     * @param _response - The response object.
     * @param next - The next function to call in the middleware chain.
     */
    private _noAuth(_request: any, _response: any, next: NextFunction): void {
        next();
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
    private _checkAuth(request: any, response: any, next: NextFunction): void {
        try {
            if (this._hashSecret) {
                if (request.session.userId == '' || !request.session.token) {
                    return response.redirect('/signin');
                }
                let decoded = verify(request.session.token, this._hashSecret);
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
    private _auth(request: any, response: any, next: NextFunction): void {
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
                let decoded = verify(token, this._hashSecret);
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

