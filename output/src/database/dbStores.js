"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbStores = void 0;
const crypto_1 = __importDefault(require("crypto"));
class DbStores {
    static init(dbDb) {
        if (dbDb == null)
            throw new Error("Missing value for dbDb");
        DbStores._dbDb = dbDb;
    }
    static get dbDb() {
        if (DbStores._dbDb == null)
            throw new Error("DbStores had not been initialized");
        return DbStores._dbDb;
    }
    static find(query) {
        return DbStores.dbDb.find(query); //.map((r) => new CertificateUtil(r));
    }
    static insert(dbRow) {
        return DbStores.dbDb.insert(dbRow);
    }
    // public static update(dbRow: DBVersionRow & LokiObj): DBVersionRow & LokiObj {
    //     return DbStores.dbDb.update(dbRow) as (DBVersionRow & LokiObj);
    // }
    static initialize(version, authenticationState, KeyEncryptionState) {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            DbStores.insert({
                version: version,
                keySecret: crypto_1.default.randomBytes(32).toString('hex'),
                passwordSecret: crypto_1.default.randomBytes(32).toString('hex'),
                authenticationState: authenticationState,
                keyEncryptionState: KeyEncryptionState
            });
        }
        else {
            throw new Error("DbStores has already been initialized");
        }
    }
    static updateVersion(version) {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found - database not initialized");
        }
        else {
            row.version = version;
            DbStores.dbDb.update(row);
        }
    }
    static getKeySecret() {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.keySecret;
    }
    static getPasswordSecret() {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.passwordSecret;
    }
    static getAuthenticationState() {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.authenticationState;
    }
    static getKeyEncryptionState() {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.keyEncryptionState;
    }
    static setKeyEncryptionState(state) {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found - database not initialized");
        }
        else {
            row.keyEncryptionState = state;
            DbStores.dbDb.update(row);
        }
    }
    static remove(dbRow) {
        return DbStores.dbDb.remove(dbRow);
    }
}
exports.DbStores = DbStores;
DbStores._dbDb = null;
//# sourceMappingURL=dbStores.js.map