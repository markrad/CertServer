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
let logger = log4js.getLogger();
class KeyUtil {
    static CreateFromPem(pemString, password) {
        return __awaiter(this, void 0, void 0, function* () {
            let k;
            let r;
            let msg = node_forge_1.pem.decode(pemString)[0];
            let encrypted = false;
            if (msg.type == 'ENCRYPTED PRIVATE KEY') {
                if (!password) {
                    logger.warn(`Encrypted key requires password`);
                    throw (new CertError_1.CertError(400, 'Password is required for key'));
                }
                k = node_forge_1.pki.decryptRsaPrivateKey(pemString, password);
                encrypted = true;
            }
            else {
                k = node_forge_1.pki.privateKeyFromPem(pemString);
            }
            r = KeyUtil._createRow(k, encrypted);
            return new KeyUtil(r, pemString);
        });
    }
    static _createRow(k, encrypted) {
        return {
            e: k.e,
            n: k.n,
            pairId: null,
            pairCN: null,
            name: null,
            type: CertTypes_1.CertTypes.key,
            encrypted: encrypted,
            $loki: undefined,
            meta: {
                created: null,
                revision: null,
                updated: null,
                version: null
            }
        };
    }
    constructor(row, pem) {
        this._pem = null;
        if (row == null) {
            throw new Error("Key row is required to construct this object");
        }
        this._row = row;
        this._pem = pem;
    }
    get row() { return this._row; }
    get e() { return this.row.e; }
    get n() { return this.row.n; }
    get pairId() { return this.row.pairId; }
    get pairCN() { return this.row.pairCN; }
    get name() { return this.row.name; }
    get type() { return this.row.type; }
    get encrypted() { return this.row.encrypted; }
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
    getOperationalResultItem() {
        return new OperationResultItem_1.OperationResultItem(this.type, this.$loki);
    }
    get keyBrief() {
        return {
            id: this.$loki,
            name: this.name,
            certPair: (this.pairId == null) ? 'Not present' : this.name.substring(0, this.name.length - 4),
            encrypted: this.encrypted,
        };
    }
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
        keyStores_1.KeyStores.keyDb.insert(this._row);
        result.pushAdded(this.getOperationalResultItem());
        if (certPair) {
            result.pushUpdated(certPair.updateKeyId(this.$loki));
        }
        return result;
    }
    setRsaPublicKey() {
        return node_forge_1.pki.setRsaPublicKey(this.n, this.e);
    }
    isIdentical(inPublicKey) {
        let myPublicKey = this.setRsaPublicKey();
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
            yield (0, promises_1.writeFile)(this.absoluteFilename, this._pem, { encoding: 'utf8' });
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
    static getIdFromFileName(name) {
        return parseInt(path_1.default.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
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
                // TODO: Should already have a flag that says it is encrypted
                try {
                    let p = yield (0, promises_1.readFile)(this.absoluteFilename, { encoding: 'utf8' });
                    let msg = node_forge_1.pem.decode(p)[0];
                    if (msg.type.startsWith('ENCRYPTED')) {
                        if (password) {
                            resolve(node_forge_1.pki.decryptRsaPrivateKey(p, password));
                        }
                        else {
                            throw new CertError_1.CertError(400, 'No password provided for encrypted key');
                        }
                    }
                    else {
                        resolve(node_forge_1.pki.privateKeyFromPem(p));
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