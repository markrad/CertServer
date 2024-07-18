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
exports.KeyUtil = void 0;
const node_forge_1 = require("node-forge");
const log4js = __importStar(require("log4js"));
const CertError_1 = require("../webservertypes/CertError");
const CertTypes_1 = require("../webservertypes/CertTypes");
const keyStores_1 = require("./keyStores");
const path_1 = __importDefault(require("path"));
const promises_1 = require("fs/promises");
const exists_1 = require("../utility/exists");
const OperationResultItem_1 = require("../webservertypes/OperationResultItem");
const OperationResult_1 = require("../webservertypes/OperationResult");
const certificateStores_1 = require("./certificateStores");
const keyEncryption_1 = require("./keyEncryption");
const dbStores_1 = require("./dbStores");
let logger = log4js.getLogger();
class KeyUtil {
    /**
     * Creates a KeyUtil instance from a PEM string.
     *
     * @param pemString - The PEM string representing the key.
     * @param password - The password to decrypt the encrypted private key (optional).
     * @returns A Promise that resolves to a KeyUtil instance.
     * @throws CertError if the key is encrypted and no password is provided.
     */
    static CreateFromPem(pemString, password) {
        return __awaiter(this, void 0, void 0, function* () {
            let k;
            let r;
            let msg = node_forge_1.pem.decode(pemString)[0];
            let encrypted = keyEncryption_1.KeyEncryption.NONE;
            if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                if (!password) {
                    logger.warn(`Encrypted key requires password`);
                    throw (new CertError_1.CertError(400, 'Password is required for key'));
                }
                k = node_forge_1.pki.decryptRsaPrivateKey(pemString, password);
                encrypted = password != keyStores_1.KeyStores.keySecret ? keyEncryption_1.KeyEncryption.USER : keyEncryption_1.KeyEncryption.SYSTEM;
            }
            else {
                k = node_forge_1.pki.privateKeyFromPem(pemString);
                if (dbStores_1.DbStores.getKeyEncryptionState()) {
                    pemString = node_forge_1.pki.encryptRsaPrivateKey(k, keyStores_1.KeyStores.keySecret);
                    encrypted = keyEncryption_1.KeyEncryption.SYSTEM;
                }
            }
            r = KeyUtil._createRow(k, encrypted);
            return new KeyUtil(r, pemString);
        });
    }
    /**
     * Creates a private key row object.
     * @param k - The RSA private key.
     * @param encryptedType - The type of key encryption.
     * @returns The private key row object.
     */
    static _createRow(k, encryptedType) {
        return {
            e: k.e,
            n: k.n,
            pairId: null,
            pairCN: null,
            name: null,
            type: CertTypes_1.CertTypes.key,
            encryptedType: encryptedType,
            $loki: undefined,
            meta: {
                created: null,
                revision: null,
                updated: null,
                version: null
            }
        };
    }
    /**
     * Creates a KeyUtil object from a database row.
     * @constructor
     * @param row - The database row representing the key.
     * @param pem - The PEM string representing the key (optional).
     */
    constructor(row, pem) {
        this._pem = null;
        if (row == null) {
            throw new Error("Key row is required to construct this object");
        }
        this._row = row;
        this._pem = pem || null;
    }
    get row() { return this._row; }
    get e() { return this.row.e; }
    get n() { return this.row.n; }
    get pairId() { return this.row.pairId; }
    get pairCN() { return this.row.pairCN; }
    get name() { return this.row.name; }
    get type() { return this.row.type; }
    get encrypted() { return this.row.encryptedType != keyEncryption_1.KeyEncryption.NONE; }
    get encryptedType() { return this.row.encryptedType; }
    /** LokiObj fields */
    get $loki() { return this.row.$loki; }
    get meta() {
        return {
            created: this.row.meta.created,
            revision: this.row.meta.revision,
            updated: this.row.meta.updated,
            version: this.row.meta.version
        };
    }
    /**
     * Generates an operational result item from this instance.
     * @returns {OperationResultItem} The operational result item.
     */
    getOperationalResultItem() {
        return new OperationResultItem_1.OperationResultItem(this.type, this.$loki);
    }
    /**
     * Returns a brief representation of the key.
     * @returns The key brief object.
     */
    get keyBrief() {
        return {
            id: this.$loki,
            name: this.name,
            certPair: (this.pairId == null) ? 'Not present' : this.name.substring(0, this.name.length - 4),
            encrypted: this.encrypted,
        };
    }
    /**
     * Encrypts the private key with the specified password and encryption type.
     * @param password - The password to encrypt the private key.
     * @param encryptedType - The encryption type to use.
     * @returns A promise that resolves to an OperationResultItem.
     */
    encrypt(password, encryptedType) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (this.encryptedType != keyEncryption_1.KeyEncryption.NONE) {
                        throw new CertError_1.CertError(400, 'Key is already encrypted');
                    }
                    let pem = this._pem ? this._pem : yield this.readFile();
                    let k = node_forge_1.pki.privateKeyFromPem(pem);
                    this._pem = node_forge_1.pki.encryptRsaPrivateKey(k, password);
                    yield this.deleteFile();
                    yield this.writeFile();
                    this._row.encryptedType = encryptedType;
                    resolve(this.update());
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Decrypts the private key using the provided password.
     * @param password - The password used for decryption.
     * @returns A Promise that resolves to an OperationResultItem.
     * @throws CertError if the key is not encrypted.
     */
    decrypt(password) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (this.encryptedType == keyEncryption_1.KeyEncryption.NONE) {
                        throw new CertError_1.CertError(400, 'Key is not encrypted');
                    }
                    let pem = this._pem ? this._pem : yield this.readFile();
                    let k = node_forge_1.pki.decryptRsaPrivateKey(pem, password);
                    this._pem = node_forge_1.pki.privateKeyToPem(k);
                    yield this.deleteFile();
                    yield this.writeFile();
                    this._row.encryptedType = keyEncryption_1.KeyEncryption.NONE;
                    resolve(this.update());
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    /**
     * Inserts a new key into the key database.
     *
     * @returns An OperationResult object representing the result of the insertion.
     */
    insert() {
        // Check for a certificate
        let cRows = certificateStores_1.CertificateStores.find({ keyId: null });
        let result = new OperationResult_1.OperationResult('unknown_key');
        let certPair = null;
        for (let c of cRows) {
            if (c.isKeyPair(this)) {
                certPair = c;
                this._row.pairCN = c.subject.CN;
                this._row.pairId = c.$loki;
                this._row.name = this._row.pairCN + '_key';
                result.name = this._row.name;
                break;
            }
        }
        if (this._row.name == null) {
            this._row.name = 'unknown_key';
        }
        keyStores_1.KeyStores.keyDb.insert(this._row);
        result.pushAdded(this.getOperationalResultItem());
        if (certPair) {
            result.pushUpdated(certPair.updateKeyId(this.$loki));
        }
        return result;
    }
    /**
     * Sets the RSA public key.
     * @returns The RSA public key.
     */
    setRsaPublicKey() {
        return node_forge_1.pki.setRsaPublicKey(this.n, this.e);
    }
    /**
     * Checks if the provided public key is identical to the current instance's public key.
     * @param inPublicKey - The public key to compare.
     * @returns `true` if the public keys are identical, `false` otherwise.
     */
    isIdentical(inPublicKey) {
        let myPublicKey = this.setRsaPublicKey();
        if (inPublicKey instanceof KeyUtil) {
            inPublicKey = inPublicKey.setRsaPublicKey();
        }
        if (myPublicKey.n.data.length != inPublicKey.n.data.length) {
            return false;
        }
        for (let i = 0; i < myPublicKey.n.data.length; i++) {
            if (myPublicKey.n.data[i] != inPublicKey.n.data[i])
                return false;
        }
        return true;
    }
    isCertificateKeyPair(c) {
        return this.isIdentical(c.publicKey);
    }
    clearCertificateKeyPair() {
        return __awaiter(this, void 0, void 0, function* () {
            let currentName = this.absoluteFilename;
            this._row.pairId = null;
            this._row.pairCN = null;
            this._row.name = 'unknown_key';
            let newName = this.absoluteFilename;
            yield (0, promises_1.rename)(currentName, newName);
            return this.update();
        });
    }
    setCertificateKeyPair(pairId, pairCN) {
        return __awaiter(this, void 0, void 0, function* () {
            let currentName = this.absoluteFilename;
            this._row.pairId = pairId;
            this._row.pairCN = pairCN;
            let newName = this.absoluteFilename;
            yield (0, promises_1.rename)(currentName, newName);
            return this.update();
        });
    }
    get absoluteFilename() {
        return path_1.default.join(keyStores_1.KeyStores.keyPath, KeyUtil._getKeyFilename(this.name, this.$loki));
    }
    writeFile() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (!this._pem)
                        throw new Error('No PEM data to write'); // This should not happen
                    yield (0, promises_1.writeFile)(this.absoluteFilename, this._pem, { encoding: 'utf8' });
                    resolve();
                }
                catch (err) {
                    reject(err);
                }
            }));
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
    /**
        * Reads the contents of the associated pem file and returns it as a string.
        * @returns A promise that resolves with the contents of the file as a string.
        */
    readFile() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield (0, promises_1.readFile)(this.absoluteFilename, { encoding: 'utf8' });
        });
    }
    static getIdFromFileName(name) {
        return parseInt(path_1.default.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }
    /**
     * Decodes a PEM string and returns an array of PEM objects.
     * @param pemString The PEM string to decode.
     * @returns An array of PEM objects.
     */
    static pemDecode(pemString) {
        return node_forge_1.pem.decode(pemString);
    }
    /**
     * Encodes a PEM object into a string.
     * @param pemObject The PEM object to encode.
     * @returns The encoded PEM object as a string.
     */
    static pemEncode(pemObject) {
        return node_forge_1.pem.encode(pemObject, { maxline: 64 });
    }
    update() {
        keyStores_1.KeyStores.keyDb.update(this.row);
        return new OperationResultItem_1.OperationResultItem(this.type, this.$loki);
    }
    remove() {
        let result = new OperationResult_1.OperationResult();
        result.pushDeleted(this.getOperationalResultItem());
        if (this.pairId) {
            let cert = certificateStores_1.CertificateStores.findOne({ $loki: this.pairId });
            if (!cert) {
                logger.warn(`Could not find certificate with id ${this.pairId}`);
            }
            else {
                result.pushUpdated(cert.updateKeyId(null));
            }
        }
        keyStores_1.KeyStores.remove(this.$loki);
        result.pushMessage(`Key ${this.name} removed`, OperationResult_1.ResultType.Success);
        return result;
    }
    getpkiKey(password) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    let p = yield (0, promises_1.readFile)(this.absoluteFilename, { encoding: 'utf8' });
                    switch (this.encryptedType) {
                        case keyEncryption_1.KeyEncryption.SYSTEM:
                            resolve(node_forge_1.pki.decryptRsaPrivateKey(p, keyStores_1.KeyStores.keySecret));
                            break;
                        case keyEncryption_1.KeyEncryption.USER:
                            if (!password) {
                                throw new CertError_1.CertError(400, 'Password required for encrypted key');
                            }
                            resolve(node_forge_1.pki.decryptRsaPrivateKey(p, password));
                            break;
                        default:
                            resolve(node_forge_1.pki.privateKeyFromPem(p));
                            break;
                    }
                    if (this.encryptedType == keyEncryption_1.KeyEncryption.USER && !password) {
                        throw new CertError_1.CertError(400, 'Password required for encrypted key');
                    }
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    getPemString() {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                try {
                    if (this.encryptedType != keyEncryption_1.KeyEncryption.SYSTEM) {
                        resolve(yield this.readFile());
                    }
                    else {
                        let k = yield this.getpkiKey();
                        resolve(node_forge_1.pki.privateKeyToPem(k));
                    }
                }
                catch (err) {
                    reject(err);
                }
            }));
        });
    }
    static _getKeyDir(filename) {
        return path_1.default.join(keyStores_1.KeyStores.keyPath, filename);
    }
    /**
     * Determines the filename of a key from the database record
     *
     * @param k key's database record
     * @returns Filename in the form of name_identity.pem
     */
    static _getKeyFilenameFromRow(k) {
        return KeyUtil._getKeyFilename(k.name, k.$loki);
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
}
exports.KeyUtil = KeyUtil;
//# sourceMappingURL=keyUtil.js.map