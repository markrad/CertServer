"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateStores = void 0;
const certificateUtil_1 = require("./certificateUtil");
class CertificateStores {
    static init(certificateDb, certificatePath) {
        if (certificateDb == null)
            throw new Error("Missing value for certficateDb");
        if (certificatePath == null)
            throw new Error("Missing value for certificatePath");
        CertificateStores._certificateDb = certificateDb;
        CertificateStores._certificatePath = certificatePath;
    }
    static get certificateDb() {
        if (CertificateStores._certificateDb == null)
            throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificateDb;
    }
    static get certificatePath() {
        if (CertificateStores._certificatePath == null)
            throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificatePath;
    }
    static find(query) {
        return CertificateStores.certificateDb.find(query).map((r) => new certificateUtil_1.CertificateUtil(r));
    }
    static findOne(query) {
        let r = CertificateStores.certificateDb.findOne(query);
        return r == null ? null : new certificateUtil_1.CertificateUtil(r);
    }
    static bulkUpdate(query, updateFunction) {
        CertificateStores.certificateDb.chain().find(query).update(updateFunction);
    }
}
exports.CertificateStores = CertificateStores;
CertificateStores._certificateDb = null;
CertificateStores._certificatePath = null;
//# sourceMappingURL=certificateStores.js.map