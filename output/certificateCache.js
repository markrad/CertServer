"use strict";
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
exports.CertificateCache = void 0;
const fs_1 = __importDefault(require("fs"));
const promises_1 = require("fs/promises");
const path_1 = __importDefault(require("path"));
const node_forge_1 = require("node-forge");
class CertificateCache {
    constructor(location, cacheTime = 10 * 60 * 60) {
        this._cache = new Map();
        if (!fs_1.default.existsSync(location)) {
            throw new Error('Specified location does not exist');
        }
        if (cacheTime < 0) {
            throw new Error('Cache time cannot be less than zero');
        }
        this._location = location;
        this._cacheTime = cacheTime;
        if (this._cacheTime > 0) {
            setInterval((this._cacheCheck), this._cacheTime * 1000);
        }
    }
    _cacheCheck() {
        this._cache.forEach((value, key, map) => {
            if (value.lastUsed + this._cacheTime < Date.now() / 1000) {
                map.delete(key);
            }
        });
    }
    getCertificate(name) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                let entry = this._cache.get(name);
                if (!entry) {
                    try {
                        entry.certificate = node_forge_1.pki.certificateFromPem(yield (0, promises_1.readFile)(path_1.default.join(this._location, name), { encoding: 'utf8' }));
                    }
                    catch (err) {
                        reject(err);
                    }
                    entry.lastUsed = Date.now() / 1000;
                    this._cache.set(name, entry);
                    resolve(entry.certificate);
                }
            }));
        });
    }
    markDirty(name) {
        this._cache.delete(name);
    }
    clearCache() {
        this._cache.clear();
    }
}
exports.CertificateCache = CertificateCache;
//# sourceMappingURL=certificateCache.js.map