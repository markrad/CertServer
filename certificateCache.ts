import fs from 'fs';
import { readFile }  from 'fs/promises';
import path from 'path'
import { pki } from 'node-forge'; 

type CacheEntry = {
    lastUsed: number;
    certificate: pki.Certificate;
}

export class CertificateCache {
    private _location: string;   
    private _cacheTime: number;
    private _cache: Map<string, CacheEntry> = new Map();
    constructor(location: string, cacheTime: number = 10 * 60 * 60) {
        if (!fs.existsSync(location)) {
            throw new Error('Specified location does not exist');
        }

        if (cacheTime < 0) {
            throw new Error('Cache time cannot be less than zero')
        }

        this._location = location;
        this._cacheTime = cacheTime;

        if (this._cacheTime > 0) {
            setInterval((this._cacheCheck), this._cacheTime * 1000);
        }
    }

    private _cacheCheck() {
        this._cache.forEach((value, key, map) => {
            if (value.lastUsed + this._cacheTime < Date.now() / 1000) {
                map.delete(key);
            }
        });
    }

    async getCertificate(name: string): Promise<pki.Certificate> {
        return new Promise<pki.Certificate>(async (resolve, reject) => {
            let entry: CacheEntry = this._cache.get(name);

            if (!entry) {
                try {
                    entry.certificate = pki.certificateFromPem(await readFile(path.join(this._location, name) ,{ encoding: 'utf8' }));
                }
                catch (err) {
                    reject(err);
                }

                entry.lastUsed = Date.now() / 1000;
                this._cache.set(name, entry);
                resolve(entry.certificate);
            }
        });
    }

    markDirty(name: string): void {
        this._cache.delete(name);
    }

    clearCache() {
        this._cache.clear();
    }
}