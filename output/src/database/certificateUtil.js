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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateUtil = void 0;
const node_forge_1 = require("node-forge");
const CertTypes_1 = require("../webservertypes/CertTypes");
// import { WebServer } from "../webserver";
const certificateStores_1 = require("./certificateStores");
const CertError_1 = require("../webservertypes/CertError");
const path_1 = __importDefault(require("path"));
const promises_1 = require("fs/promises");
const log4js = __importStar(require("log4js"));
const promises_2 = require("fs/promises");
const crypto_1 = __importDefault(require("crypto"));
const OperationResultItem_1 = require("../webservertypes/OperationResultItem");
const OperationResult_1 = require("../webservertypes/OperationResult");
const exists_1 = require("../utility/exists");
const keyStores_1 = require("./keyStores");
// import { KeyValueStore } from "lokijs";
// import { KeyStores } from "./keyStores";
// import { PrivateKeyRow } from "../webservertypes/PrivateKeyRow";
// import { KeyStores } from "./keyStores";
// import { KeyUtil } from "./keyUtil";
// import { jsbn, pki, pem, util, random, md } from 'node-forge'; 
const logger = log4js.getLogger();
class CertificateUtil {
    /**
     * Get a CertificateUtil from a PEM string
     *
     * @param pemString Certificate in PEM format
     * @returns CertificateUtil representing that input PEM file
     */
    static createFromPem(pemString) {
        return __awaiter(this, void 0, void 0, function* () {
            let msg = node_forge_1.pem.decode(pemString)[0];
            logger.debug(`Received ${msg.type}`);
            if (msg.type != 'CERTIFICATE') {
                throw new CertError_1.CertError(400, 'Unsupported type ' + msg.type);
            }
            let c = node_forge_1.pki.certificateFromPem(pemString);
            let r = yield CertificateUtil._createRow(c, pemString);
            return new CertificateUtil(r, pemString);
        });
    }
    /**
     * Get a CertificateUtil from a pki.certificate
     *
     * @param c Certificate in pki.certificate format
     * @returns CertificateUtil representing the input pki.Certificate
     */
    static createFrompkiCertificate(c) {
        return __awaiter(this, void 0, void 0, function* () {
            let p = node_forge_1.pki.certificateToPem(c);
            let r = yield CertificateUtil._createRow(c, p);
            return new CertificateUtil(r, p);
        });
    }
    /**
     * Create a database row
     *
     * @param c Certficate in pki.Certificate format
     * @param pem The same certificate in PEM format
     * @returns Row ready to write to the database
     */
    static _createRow(c, pem) {
        return __awaiter(this, void 0, void 0, function* () {
            let r = {
                name: CertificateUtil._sanitizeName(c.subject.getField('CN').value),
                type: yield CertificateUtil._calcCertType(c),
                serialNumber: c.serialNumber,
                fingerprint: new crypto_1.default.X509Certificate(pem).fingerprint,
                fingerprint256: new crypto_1.default.X509Certificate(pem).fingerprint,
                publicKey: c.publicKey,
                tags: [],
                issuer: CertificateUtil._getFields(c.issuer),
                subject: CertificateUtil._getFields(c.subject),
                notBefore: c.validity.notBefore,
                notAfter: c.validity.notAfter,
                signedById: yield (CertificateUtil._findSigner(c)),
                keyId: null,
                $loki: undefined,
                meta: {
                    created: null,
                    revision: null,
                    updated: null,
                    version: null
                }
            };
            return r;
        });
    }
    /**
     * Construct a CertificateUtl instance from a database row
     *
     * @param row Database row
     * @param pem Optional PEM version of above
     */
    constructor(row, pem) {
        this._pem = null;
        if (row == null) {
            throw new Error("Certificate row is required to construct this object");
        }
        this._row = row;
        if (pem)
            this._pem = pem;
    }
    /** Returns the database row representation */
    get row() { return this._row; }
    /** A sanitized version of the common name suitable to use as a filename (no blanks etc.) */
    get name() { return this.row.name; }
    /** The certificate type - root, intermediate, or leaf */
    get type() { return this.row.type; }
    /** The certificate's serial number */
    get serialNumber() { return this.row.serialNumber; }
    /** The SHA1 fingerprint of the certificate */
    get fingerprint() { return this.row.fingerprint; }
    /** The SHA256 fingerprint of the certificate */
    get fingerprint256() { return this.row.fingerprint256; }
    /** Public key */
    get publicKey() { return this.row.publicKey; }
    /** List of user defined tags */
    get tags() { return this.row.tags; }
    /** The $loki value of the certificate that signed this one or null if there isn't one in the system */
    get signedById() { return this.row.signedById; }
    /** The issuer's certificate subject */
    get issuer() { return this.row.issuer; }
    /** This certificate's subject */
    get subject() { return this.row.subject; }
    /** The date that this certificate is valid from */
    get notBefore() { return this.row.notBefore; }
    /** The data that this certificate is valid to */
    get notAfter() { return this.row.notAfter; }
    /** $loki value of key pair */
    get keyId() { return this.row.keyId; }
    /** LokiObj fields */
    get $loki() { return this.row.$loki; }
    /** Loki metadata */
    get meta() {
        return {
            created: this.row.meta.created,
            revision: this.row.meta.revision,
            updated: this.row.meta.updated,
            version: this.row.meta.version
        };
    }
    getOperationalResultItem() {
        return new OperationResultItem_1.OperationResultItem(this.type, this.$loki);
    }
    insert() {
        return __awaiter(this, void 0, void 0, function* () {
            if (certificateStores_1.CertificateStores.findOne({ fingerprint256: this.fingerprint256 }) != null) {
                throw new CertError_1.CertError(409, `${this.name} already exists (fingerprint256: ${this.fingerprint256}) - ignored`);
            }
            let inserted = certificateStores_1.CertificateStores.CertificateDb.insertOne(this._row);
            let updates = [];
            if (this.type == CertTypes_1.CertTypes.root) {
                updates.push(this.updateSignedById(this.$loki));
            }
            // Look for a private key
            let kRows = keyStores_1.KeyStores.find({ pairId: null });
            for (let k of kRows) {
                if (k.isCertificateKeyPair(this)) {
                    updates.push(yield k.setCertificateKeyPair(this.$loki, this.subject.CN));
                    break;
                }
            }
            // Look for certificates signed by this one
            if (this.type != CertTypes_1.CertTypes.leaf) {
                let cRows = certificateStores_1.CertificateStores.find({
                    $and: [
                        { signedById: { $eq: null } },
                        { $loki: { $ne: this.$loki } },
                        { type: { $in: [CertTypes_1.CertTypes.leaf, CertTypes_1.CertTypes.intermediate] } }
                    ]
                });
                let cpki = yield this.getpkiCert();
                for (let c of cRows) {
                    logger.debug(`Checking ${c.name}`);
                    try {
                        if (cpki.verify(yield c.getpkiCert())) {
                            updates.push(c.updateSignedById(this.$loki));
                            logger.debug(`Marked ${c.name} as signed by ${this.name}`);
                        }
                    }
                    catch (err) {
                        if (err.message != 'The parent certificate did not issue the given child certificate; the child certificate\'s issuer does not match the parent\'s subject.') {
                            logger.debug('Verify correct error: ' + err.message);
                        }
                    }
                }
            }
            return new OperationResult_1.OperationResult(inserted.name)
                .pushAdded(new OperationResultItem_1.OperationResultItem(inserted.type, inserted.$loki))
                .pushUpdated(updates);
        });
    }
    updateKeyId(id) {
        this._row.keyId = id;
        return this.update();
    }
    updateSignedById(id) {
        this._row.signedById = id;
        return this.update();
    }
    update() {
        certificateStores_1.CertificateStores.CertificateDb.update(this.row);
        return this.getOperationalResultItem();
    }
    remove() {
        let saveLoki = this.$loki;
        certificateStores_1.CertificateStores.CertificateDb.remove(this.row);
        // TODO: Remove id from key pair and update any certificates signed by this one
        return new OperationResultItem_1.OperationResultItem(this.type, saveLoki);
    }
    get absoluteFilename() {
        return path_1.default.join(certificateStores_1.CertificateStores.CertificatePath, CertificateUtil._getKeyFilename(this.name, this.$loki));
    }
    writeFile() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                try {
                    if (!this._pem) {
                        // This would typically mean that the file already exists
                        throw new Error("Logic error: pem is not available to write");
                    }
                    (0, promises_1.writeFile)(this.absoluteFilename, this._pem, { encoding: 'utf8' });
                    resolve();
                }
                catch (err) {
                    reject(err);
                }
            });
            (0, promises_1.writeFile)(this.absoluteFilename, this._pem);
        });
    }
    deleteFile() {
        return __awaiter(this, void 0, void 0, function* () {
            if (yield (0, exists_1.exists)(this.absoluteFilename)) {
                yield (0, promises_1.unlink)(this.absoluteFilename);
                return true;
            }
            else {
                return false;
            }
        });
    }
    getpkiCert() {
        return __awaiter(this, void 0, void 0, function* () {
            return node_forge_1.pki.certificateFromPem(this._pem ? this._pem : yield (0, promises_2.readFile)(this.absoluteFilename, { encoding: 'utf8' }));
        });
    }
    isKeyPair(key) {
        return key.isIdentical(this.publicKey);
    }
    /**
     * Determines the filename for a key
     *
     * @param name Name in the key record
     * @param $loki Identity in the key record
     * @returns Filename in the form of name_identity.pem
     */
    static _getKeyFilename(name, $loki) {
        return `${name}_${$loki}.pem`;
    }
    static _sanitizeName(name) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }
    static _getFields(s) {
        let getValue = (v) => {
            let work = s.getField(v);
            return work ? work.value : null;
        };
        return {
            C: getValue('C'),
            ST: getValue('ST'),
            L: getValue('L'),
            O: getValue('O'),
            OU: getValue('OU'),
            CN: getValue('CN')
        };
    }
    static _calcCertType(c) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            let type;
            // let signedById: number;
            if (c.isIssuer(c)) {
                type = CertTypes_1.CertTypes.root;
                // signedById = -1;
            }
            else {
                let bc = c.getExtension('basicConstraints');
                if ((bc != null) && ((_a = bc.cA) !== null && _a !== void 0 ? _a : false) == true && ((_b = bc.pathlenConstraint) !== null && _b !== void 0 ? _b : 1) > 0) {
                    type = CertTypes_1.CertTypes.intermediate;
                }
                else {
                    type = CertTypes_1.CertTypes.leaf;
                }
                // See if any existing certificates signed this one
                // let signer = await CertificateUtil._findSigner(c);
                // if (signer != null) {
                //     // signedById = signer.$loki;
                // }
            }
            return type;
        });
    }
    static _findSigner(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
                let i;
                let rowList = certificateStores_1.CertificateStores.find({ 'type': { '$in': [CertTypes_1.CertTypes.root, CertTypes_1.CertTypes.intermediate] } });
                for (i = 0; i < rowList.length; i++) {
                    try {
                        let r = yield rowList[i].getpkiCert();
                        if (r.verify(c)) {
                            resolve(rowList[i].$loki);
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
                if (i == rowList.length) {
                    resolve(null);
                }
            }));
        });
    }
}
exports.CertificateUtil = CertificateUtil;
//# sourceMappingURL=certificateUtil.js.map