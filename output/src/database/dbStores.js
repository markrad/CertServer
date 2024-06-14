"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbStores = void 0;
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
    static update(dbRow) {
        return DbStores.dbDb.update(dbRow);
    }
    static updateVersion(version) {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            DbStores.insert({ version: version, keySecret: null });
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
    static updateKeySecret(keySecret) {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found");
        }
        else {
            row.keySecret = keySecret;
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