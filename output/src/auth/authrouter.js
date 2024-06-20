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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthRouter = void 0;
const express_1 = require("express");
const jsonwebtoken_1 = require("jsonwebtoken");
const log4js = __importStar(require("log4js"));
const userStore_1 = require("../database/userStore");
const CertError_1 = require("../webservertypes/CertError");
const CertMultiError_1 = require("../webservertypes/CertMultiError");
const logger = log4js.getLogger('CertServer');
const tokenLife = '5m';
/**
 * @classdesc Represents a router for handling authentication-related routes.
 */
class AuthRouter {
    /**
     * @constructor
     * @param hashSecret - The secret key used to hash the JWT token. If not provided, the router will not require authentication.
     */
    constructor(hashSecret) {
        this._authRouter = (0, express_1.Router)();
        this._authPtr = this._noAuth;
        this._checkAuthPtr = this._noAuth;
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
        this._authRouter.post('/login', (request, response) => __awaiter(this, void 0, void 0, function* () {
            try {
                const { userId, password } = request.body;
                logger.debug(`Login request - User: ${userId}`);
                if (userStore_1.UserStore.authenticate(userId, password)) {
                    let { token, expiresAt } = yield this.generateToken(userId, this._hashSecret, tokenLife);
                    request.session.userId = userId;
                    request.session.token = token;
                    request.session.lastSignedIn = new Date();
                    request.session.tokenExpiration = expiresAt;
                    logger.debug('Login successful');
                    return response.status(200).json({ success: true, token: token, userId: userId, expiresAt: expiresAt });
                }
                else {
                    throw new CertError_1.CertError(401, 'Invalid credentials');
                }
            }
            catch (err) {
                logger.error(err.message);
                let e = CertMultiError_1.CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        }));
        this._authRouter.post('/tokenrefresh', this.auth, (request, response) => __awaiter(this, void 0, void 0, function* () {
            try {
                if (!request.session.token) {
                    throw new CertError_1.CertError(401, 'You must be logged in to refresh a token');
                }
                let { token, expiresAt } = yield this.generateToken(request.session.userId, this._hashSecret, tokenLife);
                request.session.token = token;
                request.session.tokenExpiration = expiresAt;
                logger.debug('Token refresh successful');
                return response.status(200).json({ success: true, token: token, expiresAt: expiresAt });
            }
            catch (err) {
                logger.error(err.message);
                let e = CertMultiError_1.CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        }));
        this._authRouter.post('/token', this.auth, (request, response) => __awaiter(this, void 0, void 0, function* () {
            try {
                // Returns a shortlived token to be used for a WebSockets connection
                if (!request.session.token) {
                    throw new CertError_1.CertError(401, 'You must be logged in to get a temporary token');
                }
                let decoded = yield this.verifyToken(request.session.token, this._hashSecret);
                logger.debug(decoded);
                if (decoded.userId != request.session.userId) {
                    throw new CertError_1.CertError(401, 'You can only get a token for your own session');
                }
                let token = yield this.generateToken(decoded.userId, this._hashSecret, 5);
                logger.debug('Temporary token creation successful');
                return response.status(200).json({ success: true, token: token.token });
            }
            catch (err) {
                logger.error(err.message);
                let e = CertMultiError_1.CertMultiError.getCertError(err);
                return response.status(e.status).json(e.getResponse());
            }
        }));
        this._authRouter.get('/authrequired', (_request, response) => {
            response.status(200).json({ authRequired: this._hashSecret != null });
        });
    }
    /**
     * Gets the router for handling authentication routes.
     * @returns The authentication router.
     */
    get router() {
        return this._authRouter;
    }
    /**
     * Authenticates a request to open a WebSocket connection.
     * @param request - The incoming HTTP request.
     * @param socket - The socket connection.
     * @throws {CertError} - If the token is not provided or the user does not exist.
     */
    socketUpgrade(request, socket) {
        let token = null;
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
                throw new CertError_1.CertError(401, 'No token provided');
            }
            let decoded = (0, jsonwebtoken_1.verify)(token, this._hashSecret);
            logger.debug(decoded);
            if (!userStore_1.UserStore.getUser(decoded.userId)) {
                socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                socket.end();
                throw new CertError_1.CertError(401, `User ${decoded.userId} not found`);
            }
        }
    }
    /**
     * Returns the authentication middleware function.
     * @returns The authentication middleware function.
     */
    get auth() {
        return this._authPtr.bind(this);
    }
    /**
     * Returns the middleware function for checking authentication.
     * @returns A middleware function that checks authentication.
     */
    get checkAuth() {
        return this._checkAuthPtr.bind(this);
    }
    /**
     * Middleware function that allows the request to proceed without authentication.
     * @param _request - The request object.
     * @param _response - The response object.
     * @param next - The next function to call in the middleware chain.
     */
    _noAuth(_request, _response, next) {
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
    _checkAuth(request, response, next) {
        try {
            if (this._hashSecret) {
                if (request.session.userId == '' || !request.session.token) {
                    return response.redirect('/signin');
                }
                let decoded = (0, jsonwebtoken_1.verify)(request.session.token, this._hashSecret);
                logger.debug(decoded);
                if (!userStore_1.UserStore.getUser(decoded.userId)) {
                    throw new CertError_1.CertError(401, `User ${decoded.userId} not found`);
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
    _auth(request, response, next) {
        try {
            if (this._hashSecret) {
                let token = null;
                if (request.headers.authorization) {
                    token = request.headers.authorization.split(' ')[1];
                }
                else if (request.session.token) {
                    token = request.session.token;
                }
                else {
                    throw new CertError_1.CertError(401, 'No token provided');
                }
                let decoded = (0, jsonwebtoken_1.verify)(token, this._hashSecret);
                logger.debug(decoded);
                if (!userStore_1.UserStore.getUser(decoded.userId)) {
                    throw new CertError_1.CertError(401, `User ${decoded.userId} not found`);
                }
            }
            next();
        }
        catch (err) {
            logger.warn(err.message);
            let e;
            if (err instanceof jsonwebtoken_1.JsonWebTokenError) {
                e = new CertError_1.CertError(401, err.message);
            }
            else {
                e = CertMultiError_1.CertMultiError.getCertError(err);
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
    verifyToken(token, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                (0, jsonwebtoken_1.verify)(token, secret, (err, decoded) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(decoded);
                    }
                });
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
    generateToken(userId, secret, expires) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                (0, jsonwebtoken_1.sign)({ userId: userId }, secret, { expiresIn: expires }, (err, token) => {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve({ token: token, expiresAt: (0, jsonwebtoken_1.decode)(token).exp });
                    }
                });
            });
        });
    }
}
exports.AuthRouter = AuthRouter;
//# sourceMappingURL=authrouter.js.map