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
const ExtensionBasicConstraints_1 = require("../extensions/ExtensionBasicConstraints");
const ExtensionKeyUsage_1 = require("../extensions/ExtensionKeyUsage");
const ExtensionSubjectKeyIdentifier_1 = require("../extensions/ExtensionSubjectKeyIdentifier");
const ExtensionAuthorityKeyIdentifier_1 = require("../extensions/ExtensionAuthorityKeyIdentifier");
const ExtensionExtKeyUsage_1 = require("../extensions/ExtensionExtKeyUsage");
const ExtensionSubjectAltName_1 = require("../extensions/ExtensionSubjectAltName");
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
        var _a, _b;
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
                signedById: ((_b = (_a = (yield CertificateUtil._findSigner(c))) === null || _a === void 0 ? void 0 : _a.$loki) !== null && _b !== void 0 ? _b : null),
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
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (certificateStores_1.CertificateStores.findOne({ fingerprint256: this.fingerprint256 }) != null) {
                        reject(new CertError_1.CertError(409, `${this.name} already exists (fingerprint256: ${this.fingerprint256}) - ignored`));
                        return;
                    }
                    let inserted = certificateStores_1.CertificateStores.certificateDb.insertOne(this._row);
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
                    resolve(new OperationResult_1.OperationResult(inserted.name)
                        .pushAdded(new OperationResultItem_1.OperationResultItem(inserted.type, inserted.$loki))
                        .pushUpdated(updates));
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Updates the key ID of the certificate.
     *
     * @param id - The new key ID to be set.
     * @returns An `OperationResultItem` representing the result of the update operation.
     */
    updateKeyId(id) {
        this._row.keyId = id;
        return this.update();
    }
    /**
     * Updates the signedById property of the certificateUtil instance.
     *
     * @param id - The ID of the certificate that signed this certificate.
     * @returns An OperationResultItem indicating the result of the update operation.
     */
    updateSignedById(id) {
        this._row.signedById = id;
        return this.update();
    }
    /**
     * Updates the tags of the certificate.
     * @param tags - An array of strings representing the new tags for the certificate.
     * @returns An OperationResultItem object representing the result of the update operation.
     */
    updateTags(tags) {
        this._row.tags = tags;
        return this.update();
    }
    /**
     * Updates the certificate in the certificate database.
     *
     * @returns {OperationResultItem} The operation result item.
     */
    update() {
        certificateStores_1.CertificateStores.certificateDb.update(this.row);
        return this.getOperationalResultItem();
    }
    /**
     * Removes the certificate from the database.
     * @returns A Promise that resolves to an OperationResult indicating the success of the removal operation.
     */
    remove() {
        return __awaiter(this, void 0, void 0, function* () {
            let result = new OperationResult_1.OperationResult('');
            result.pushDeleted(this.getOperationalResultItem());
            let key = keyStores_1.KeyStores.findOne({ $loki: this.keyId });
            if (key) {
                result.pushUpdated(yield key.clearCertificateKeyPair());
            }
            certificateStores_1.CertificateStores.bulkUpdate({ $and: [{ signedById: this.$loki }, { $loki: { $ne: this.$loki } }] }, (cert) => {
                cert.signedById = null;
                result.pushUpdated(new OperationResultItem_1.OperationResultItem(cert.type, cert.$loki));
            });
            certificateStores_1.CertificateStores.certificateDb.remove(this.row);
            result.pushMessage(`Certificate ${this.name} removed`, OperationResult_1.ResultType.Success);
            return result;
        });
    }
    /**
     * Returns a brief representation of the certificate required for display on the web interface.
     * @returns {CertificateBrief} The brief representation of the certificate.
     */
    certificateBrief() {
        var _a;
        let c = null;
        if (this.signedById != null) {
            c = certificateStores_1.CertificateStores.findOne({ $loki: this.signedById });
            if (c == null) {
                logger.warn(`Signing certificate missing for ${c.name}`);
            }
        }
        let s = certificateStores_1.CertificateStores.find({ signedById: this.$loki }).map((r) => r.$loki);
        return {
            id: this.$loki,
            certType: CertTypes_1.CertTypes[this.type],
            name: this.subject.CN,
            issuer: this.issuer,
            subject: this.subject,
            validFrom: this.notBefore,
            validTo: this.notAfter,
            serialNumber: this.serialNumber == null ? '' : this.serialNumber.match(/.{1,2}/g).join(':'),
            signer: c ? c.subject.CN : null,
            signerId: c ? c.$loki : null,
            keyId: this.keyId,
            fingerprint: this.fingerprint,
            fingerprint256: this.fingerprint256,
            signed: s,
            tags: (_a = this.tags) !== null && _a !== void 0 ? _a : [],
        };
    }
    /**
     * Retrieves the certificate chain by reading the contents of each certificate file.
     * The chain is constructed by starting from the current certificate and following the `signedById` property.
     * Each certificate file is read using the `readFile` function with 'utf8' encoding.
     *
     * @returns A Promise that resolves to a string representing the concatenated contents of all the certificate files in the chain.
     * @throws {CertError} If a certificate row with the specified `signedById` is not found in the database.
     */
    getCertificateChain() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let file;
                    file = yield (0, promises_2.readFile)(this.absoluteFilename, { encoding: 'utf8' });
                    let s = this.signedById;
                    while (s != null) {
                        let c = certificateStores_1.CertificateStores.findOne({ $loki: s });
                        if (c == null) {
                            throw new CertError_1.CertError(500, `Expected certificate row with id ${s}`);
                        }
                        file += yield (0, promises_2.readFile)(c.absoluteFilename, { encoding: 'utf8' });
                        s = c.signedById == c.$loki ? null : c.signedById;
                    }
                    resolve(file);
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Gets the absolute filename of the certificate.
     * The absolute filename is determined by joining the certificate path with the key filename.
     * @returns The absolute filename of the certificate.
     */
    get absoluteFilename() {
        return path_1.default.join(certificateStores_1.CertificateStores.certificatePath, CertificateUtil._getKeyFilename(this.name, this.$loki));
    }
    /**
     * Writes the PEM content to a file.
     * @returns A Promise that resolves when the file is successfully written, or rejects with an error if there was a problem.
     */
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
    /**
     * Deletes the file associated with this certificate.
     *
     * @returns A promise that resolves to `true` if the file is successfully deleted, or `false` if the file does not exist.
     */
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
    /**
     * Retrieves the PKI certificate.
     * If the certificate is already available in memory, it returns it.
     * Otherwise, it reads the certificate from the file system and returns it.
     * @returns A Promise that resolves to the PKI certificate.
     */
    getpkiCert() {
        return __awaiter(this, void 0, void 0, function* () {
            return node_forge_1.pki.certificateFromPem(this._pem ? this._pem : yield (0, promises_2.readFile)(this.absoluteFilename, { encoding: 'utf8' }));
        });
    }
    /**
     * Finds the signer of the certificate.
     * @returns A Promise that resolves to a CertificateUtil instance representing the signer.
     */
    findSigner() {
        return __awaiter(this, void 0, void 0, function* () {
            return CertificateUtil._findSigner(yield this.getpkiCert());
        });
    }
    /**
     * Checks if the given key is a key pair.
     * @param key - The key to check.
     * @returns True if the key is a key pair, false otherwise.
     */
    isKeyPair(key) {
        return key.isIdentical(this.publicKey);
    }
    /**
     * Generates a certificate pair consisting of a certificate and a private key.
     *
     * @param type - The type of certificate to generate.
     * @param body - The input data for generating the certificate.
     * @returns A promise that resolves to an object containing the generated certificate PEM, key PEM, and the result of the operation.
     * @throws {CertError} If an error occurs during the generation process.
     */
    static generateCertificatePair(type, body) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let result = new OperationResult_1.OperationResult('');
                    let { certificateInput, messages } = CertificateUtil._validateCertificateInput(type, body);
                    if (messages.hasErrors) {
                        resolve({ certificatePem: null, keyPem: null, result: messages });
                        return;
                    }
                    const cRow = type == CertTypes_1.CertTypes.root ? null : certificateStores_1.CertificateStores.findOne({ $loki: parseInt(certificateInput.signer) });
                    const kRow = type == CertTypes_1.CertTypes.root ? null : keyStores_1.KeyStores.findOne({ $loki: cRow.keyId });
                    if (type != CertTypes_1.CertTypes.root && (!cRow || !kRow)) {
                        resolve({ certificatePem: null, keyPem: null, result: result.pushMessage('Signing certificate or key are either missing or invalid', OperationResult_1.ResultType.Failed) });
                        return;
                    }
                    const c = type == CertTypes_1.CertTypes.root ? null : yield cRow.getpkiCert();
                    const k = type == CertTypes_1.CertTypes.root ? null : yield kRow.getpkiKey(certificateInput.password);
                    const { privateKey, publicKey } = node_forge_1.pki.rsa.generateKeyPair(2048);
                    const attributes = CertificateUtil._setAttributes(certificateInput.subject);
                    const extensions = [];
                    if (type != CertTypes_1.CertTypes.leaf) {
                        extensions.push(new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: true, critical: true }));
                        extensions.push(new ExtensionKeyUsage_1.ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }));
                    }
                    if (type != CertTypes_1.CertTypes.root) {
                        extensions.push(new ExtensionAuthorityKeyIdentifier_1.ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }));
                    }
                    if (type == CertTypes_1.CertTypes.leaf) {
                        extensions.push(new ExtensionBasicConstraints_1.ExtensionBasicConstraints({ cA: false }));
                        extensions.push(new ExtensionKeyUsage_1.ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }));
                        extensions.push(new ExtensionExtKeyUsage_1.ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true, }));
                        extensions.push(new ExtensionSubjectAltName_1.ExtensionSubjectAltName(certificateInput.san));
                    }
                    extensions.push(new ExtensionSubjectKeyIdentifier_1.ExtensionSubjectKeyIdentifier({}));
                    // Create an empty Certificate
                    let cert = node_forge_1.pki.createCertificate();
                    cert.publicKey = publicKey;
                    // cert.privateKey = privateKey;
                    cert.serialNumber = CertificateUtil._getRandomSerialNumber();
                    cert.validity.notBefore = certificateInput.validFrom;
                    cert.validity.notAfter = certificateInput.validTo;
                    cert.setSubject(attributes);
                    cert.setIssuer(type == CertTypes_1.CertTypes.root ? attributes : c.subject.attributes);
                    cert.setExtensions(extensions.map((extension) => extension.getObject()));
                    // Self-sign root but use the signer's key for the others
                    cert.sign(type == CertTypes_1.CertTypes.root ? privateKey : k, node_forge_1.md.sha512.create());
                    resolve({ certificatePem: node_forge_1.pki.certificateToPem(cert), keyPem: node_forge_1.pki.privateKeyToPem(privateKey), result: result });
                }
                catch (err) {
                    reject(new CertError_1.CertError(500, err.message));
                }
            }));
        });
    }
    /**
     * Extracts the ID from a given file name.
     *
     * @param name - The file name from which to extract the ID.
     * @returns The extracted ID as a number.
     */
    static getIdFromFileName(name) {
        return parseInt(path_1.default.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
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
    /**
     * Sanitizes the given name by replacing any characters that are not alphanumeric, underscore, hyphen, equal sign, plus sign, curly braces, square brackets, parentheses, double quotes, or single quotes with an underscore.
     *
     * @param name - The name to be sanitized.
     * @returns The sanitized name.
     */
    static _sanitizeName(name) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }
    /**
     * Retrieves the fields from the issuer or subject of a certificate.
     *
     * @param s - The issuer or subject of a certificate.
     * @returns An object containing the values of the fields.
     */
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
    /**
     * Calculates the type of the certificate.
     * @param c - The certificate to calculate the type for.
     * @returns A promise that resolves to the type of the certificate.
     */
    static _calcCertType(c) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            let type = null;
            // let signedById: number;
            try {
                c.verify(c);
                type = CertTypes_1.CertTypes.root;
            }
            catch (_err) {
                // Don't care - verify throws an error rather than returning a boolean
            }
            // if (c.verify(c)) { 
            //     type = CertTypes.root;
            //     // signedById = -1;
            // }
            if (type == null) {
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
    /**
     * Finds the signer certificate for the given certificate.
     * @param c - The certificate for which to find the signer.
     * @returns A Promise that resolves with the signer certificate, or null if not found.
     */
    static _findSigner(c) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
                let i;
                let rowList = certificateStores_1.CertificateStores.find({ 'type': { '$in': [CertTypes_1.CertTypes.root, CertTypes_1.CertTypes.intermediate] } });
                for (i = 0; i < rowList.length; i++) {
                    try {
                        let r = yield rowList[i].getpkiCert();
                        if (r.verify(c)) {
                            resolve(rowList[i]);
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
    /**
     * Validates the certificate input and returns the certificate input object and operation result.
     * @param type - The type of certificate.
     * @param bodyIn - The input body containing certificate details.
     * @returns An object containing the certificate input and operation result.
     * @throws {CertError} If there is an error in the certificate input.
     */
    static _validateCertificateInput(type, bodyIn) {
        var _a, _b;
        // FUTURE Needs a mechanism to force parts of the RDA sequence to be omitted
        try {
            if (typeof bodyIn !== 'object') {
                throw new CertError_1.CertError(400, 'Bad POST data format - use Content-type: application/json');
            }
            let body = bodyIn;
            let result = {
                validFrom: body.validFrom ? new Date(body.validFrom) : new Date(),
                validTo: new Date(body.validTo),
                signer: (_a = body.signer) !== null && _a !== void 0 ? _a : null,
                password: (_b = body.password) !== null && _b !== void 0 ? _b : null,
                subject: {
                    C: body.country ? body.country : null,
                    ST: body.state ? body.state : null,
                    L: body.location ? body.location : null,
                    O: body.organization ? body.organization : null,
                    OU: body.unit ? body.unit : null,
                    CN: body.commonName ? body.commonName : null
                },
                san: {
                    domains: [],
                    IPs: [],
                }
            };
            let opResults = new OperationResult_1.OperationResult('Generate Certificate');
            if (!result.subject.CN)
                opResults.pushMessage('Common name is required', OperationResult_1.ResultType.Failed);
            if (!result.validTo)
                opResults.pushMessage('Valid to is required', OperationResult_1.ResultType.Failed);
            if (type != CertTypes_1.CertTypes.root && !body.signer)
                opResults.pushMessage('Signing certificate is required', OperationResult_1.ResultType.Failed);
            if (isNaN(result.validTo.valueOf()))
                opResults.pushMessage('Valid to is invalid', OperationResult_1.ResultType.Failed);
            if (body.validFrom && isNaN(result.validFrom.valueOf()))
                opResults.pushMessage('Valid from is invalid', OperationResult_1.ResultType.Failed);
            if (result.subject.C != null && result.subject.C.length != 2)
                opResults.pushMessage('Country code must be omitted or have two characters', OperationResult_1.ResultType.Failed);
            let rc = CertificateUtil._isValidRNASequence([result.subject.C, result.subject.ST, result.subject.L, result.subject.O, result.subject.OU, result.subject.CN]);
            if (rc)
                opResults.pushMessage(rc.message, rc.type);
            if (opResults.hasErrors) {
                opResults.setStatusCode(400);
                return { certificateInput: null, messages: opResults };
            }
            if (type == CertTypes_1.CertTypes.leaf) {
                result.san.domains.push(body.commonName);
            }
            if (type != CertTypes_1.CertTypes.root && body.SANArray) {
                let SANArray = Array.isArray(body.SANArray) ? body.SANArray : [body.SANArray];
                let domains = SANArray.filter((entry) => entry.startsWith('DNS:')).map((entry) => entry.split(' ')[1]);
                let ips = SANArray.filter((entry) => entry.startsWith('IP:')).map((entry) => entry.split(' ')[1]);
                if (domains.length > 0)
                    result.san.domains = result.san.domains.concat(domains);
                if (ips.length > 0)
                    result.san.IPs = ips;
            }
            return { certificateInput: result, messages: opResults };
        }
        catch (err) {
            throw new CertError_1.CertError(500, err.message);
        }
    }
    /**
     * Validates RNA strings to ensure they consist only of characters allowed in those strings. The node-forge package does not enforce this.
     *
     * @param rnas Array of RNA values for validation
     * @returns {{valid: boolean, message?: string}} valid: true if all are valid otherwise valid: false, message: error message
     */
    static _isValidRNASequence(rnas) {
        for (let r in rnas) {
            if (!/^[a-z A-Z 0-9'\=\(\)\+\,\-\.\/\:\?]*$/.test(rnas[r])) {
                return { message: 'Subject contains an invalid character', type: OperationResult_1.ResultType.Failed };
            }
        }
        return null;
    }
    /**
     * Generates a certificate serial number
     *
     * @returns A random number to use as a certificate serial number
     */
    static _getRandomSerialNumber() {
        return CertificateUtil._makeNumberPositive(node_forge_1.util.bytesToHex(node_forge_1.random.getBytesSync(20)));
    }
    /**
     * Add subject values to pki.CertificateField
     *
     * @param subject Subject fields for the certificate
     * @returns pki.CertificateField with the provided fields
     */
    static _setAttributes(subject) {
        let attributes = [];
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
}
exports.CertificateUtil = CertificateUtil;
/**
 * If the passed number is negative it is made positive
 *
 * @param hexString String containing a hexadecimal number
 * @returns Positive version of the input
 */
CertificateUtil._makeNumberPositive = (hexString) => {
    let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);
    if (mostSignificativeHexDigitAsInt < 8)
        return hexString;
    mostSignificativeHexDigitAsInt -= 8;
    return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
};
//# sourceMappingURL=certificateUtil.js.map