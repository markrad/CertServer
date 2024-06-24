"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyStores = void 0;
const keyUtil_1 = require("./keyUtil");
const dbStores_1 = require("./dbStores");
class KeyStores {
    static init(privateKeyDb, privateKeyPath /*, keySecret: string*/) {
        if (privateKeyDb == null)
            throw new Error("Missing value for privateKeyDb");
        if (privateKeyPath == null)
            throw new Error("Missing value for privateKeyPath");
        KeyStores._privateKeyDb = privateKeyDb;
        KeyStores._privateKeyPath = privateKeyPath;
    }
    static get keyDb() {
        if (KeyStores._privateKeyDb == null)
            throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyDb;
    }
    static get keyPath() {
        if (KeyStores._privateKeyPath == null)
            throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyPath;
    }
    static get keySecret() {
        return dbStores_1.DbStores.getKeySecret();
    }
    static find(query) {
        return KeyStores.keyDb.find(query).map((r) => new keyUtil_1.KeyUtil(r));
    }
    static findOne(query) {
        let r = KeyStores.keyDb.findOne(query);
        return r == null ? null : new keyUtil_1.KeyUtil(r);
    }
    static remove(id) {
        KeyStores.keyDb.remove(id);
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