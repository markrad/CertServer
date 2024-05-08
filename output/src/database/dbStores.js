"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DbStores = void 0;
class DbStores {
    static Init(dbDb) {
        if (dbDb == null)
            throw new Error("Missing value for dbDb");
        DbStores._dbDb = dbDb;
    }
    static get DbDb() {
        if (DbStores._dbDb == null)
            throw new Error("DbStores had not been initialized");
        return DbStores._dbDb;
    }
    static find(query) {
        return DbStores.DbDb.find(query); //.map((r) => new CertificateUtil(r));
    }
    static insert(dbRow) {
        return DbStores.DbDb.insert(dbRow);
    }
    static update(dbRow) {
        return DbStores.DbDb.update(dbRow);
    }
    static remove(dbRow) {
        return DbStores.DbDb.remove(dbRow);
    }
}
exports.DbStores = DbStores;
DbStores._dbDb = null;
//# sourceMappingURL=dbStores.js.map