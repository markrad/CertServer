"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyStores = void 0;
const keyUtil_1 = require("./keyUtil");
// import { CertificateUtil } from "./certificateUtil";
// import { CertificateStores } from "./certificateStores";
class KeyStores {
    static Init(privateKeyDb, privateKeyPath) {
        if (privateKeyDb == null)
            throw new Error("Missing value for privateKeyDb");
        if (privateKeyPath == null)
            throw new Error("Missing value for privateKeyPath");
        KeyStores._privateKeyDb = privateKeyDb;
        KeyStores._privateKeyPath = privateKeyPath;
    }
    static get KeyDb() {
        if (KeyStores._privateKeyDb == null)
            throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyDb;
    }
    static get KeyPath() {
        if (KeyStores._privateKeyPath == null)
            throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyPath;
    }
    static find(query) {
        return KeyStores.KeyDb.find(query).map((r) => new keyUtil_1.KeyUtil(r));
    }
    static findOne(query) {
        let r = KeyStores.KeyDb.findOne(query);
        return r == null ? null : new keyUtil_1.KeyUtil(r);
    }
    static remove(id) {
        KeyStores.KeyDb.remove(id);
    }
    static isIdentical(k) {
        let keyIn = k.setRsaPublicKey();
        let allKeys = KeyStores.find();
        for (let iKey in allKeys) {
            if (allKeys[iKey].isIdentical(keyIn)) {
                return allKeys[iKey];
            }
        }
        return null;
    }
}
exports.KeyStores = KeyStores;
KeyStores._privateKeyDb = null;
KeyStores._privateKeyPath = null;
//# sourceMappingURL=keyStores.js.map