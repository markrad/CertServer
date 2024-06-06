import { jsbn, pem, pki } from "node-forge";
import { PrivateKeyRow } from "./PrivateKeyRow";

import * as log4js from "log4js";
import { CertError } from "../webservertypes/CertError";
import { CertTypes } from "../webservertypes/CertTypes";
import { KeyStores } from "./keyStores";

import Path from "path";
import { unlink, writeFile, rename, readFile } from "fs/promises";
import { KeyBrief } from "../webservertypes/KeyBrief";
import { exists } from "../utility/exists";
import { OperationResultItem } from "../webservertypes/OperationResultItem";
import { OperationResult, ResultType } from "../webservertypes/OperationResult";
import { CertificateUtil } from "./certificateUtil";
import { CertificateStores } from "./certificateStores";

let logger = log4js.getLogger();

export class KeyUtil implements PrivateKeyRow, LokiObj {
    private _row: PrivateKeyRow & LokiObj;
    private _pem: string = null;

    public static async CreateFromPem(pemString: string, password?: string): Promise<KeyUtil> {
        let k: pki.rsa.PrivateKey;
        let r: PrivateKeyRow & LokiObj;
        let msg = pem.decode(pemString)[0];
        let encrypted: boolean = false;
        if (msg.type == 'ENCRYPTED PRIVATE KEY') {
            if (!password) {
                logger.warn(`Encrypted key requires password`);
                throw(new CertError(400, 'Password is required for key'));
            }
            k = pki.decryptRsaPrivateKey(pemString, password);
            encrypted = true;
        }
        else {
            k = pki.privateKeyFromPem(pemString);
        }

        r = KeyUtil._createRow(k, encrypted);
        
        return new KeyUtil(r, pemString);
    }

    private static _createRow(k: pki.rsa.PrivateKey, encrypted: boolean): PrivateKeyRow & LokiObj {
        return {
            e: k.e,
            n: k.n,
            pairId: null,
            pairCN: null,
            name: null,
            type: CertTypes.key,
            encrypted: encrypted,
            $loki: undefined,
            meta: {
                created: null,
                revision: null,
                updated: null,
                version: null
            }
        }
    }

    public constructor(row: PrivateKeyRow & LokiObj, pem?: string) {
        if (row == null) { throw new Error("Key row is required to construct this object"); }
        this._row = row;
        this._pem = pem;
    }

    public get row(): PrivateKeyRow & LokiObj { return this._row; }
    public get e(): jsbn.BigInteger { return this.row.e; }
    public get n(): jsbn.BigInteger { return this.row.n; }
    public get pairId(): number { return this.row.pairId; }
    public get pairCN(): string { return this.row.pairCN; }
    public get name(): string { return this.row.name; }
    public get type(): CertTypes { return this.row.type; }
    public get encrypted(): boolean { return this.row.encrypted; }

    /** LokiObj fields */
    public get $loki(): number { return this.row.$loki }
    public get meta() {
        return {
            created: this.row.meta.created,
            revision: this.row.meta.revision,
            updated: this.row.meta.updated,
            version: this.row.meta.version
        }
    } 

    public getOperationalResultItem(): OperationResultItem {
        return new OperationResultItem(this.type, this.$loki);
    }

    public get keyBrief(): KeyBrief {
        return {
            id: this.$loki,
            name: this.name,
            certPair: (this.pairId == null) ? 'Not present' : this.name.substring(0, this.name.length - 4),
            encrypted: this.encrypted,
        }
    }

    public insert(): OperationResult {
        // Check for a certificate
        let cRows: CertificateUtil[] = CertificateStores.find({ keyId: null });
        let result: OperationResult = new OperationResult('unknown_key');
        let certPair: CertificateUtil = null;

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
        KeyStores.keyDb.insert(this._row);
        result.pushAdded(this.getOperationalResultItem());

        if (certPair) {
            result.pushUpdated(certPair.updateKeyId(this.$loki));
        }

        return result;
    }

    public setRsaPublicKey(): pki.rsa.PublicKey {
        return pki.setRsaPublicKey(this.n, this.e);
    }

    public isIdentical(inPublicKey: pki.rsa.PublicKey): boolean {
        let myPublicKey = this.setRsaPublicKey();

        if (myPublicKey.n.data.length != inPublicKey.n.data.length) {
            return false;
        }

        for (let i = 0; i < myPublicKey.n.data.length; i++) {
            if (myPublicKey.n.data[i] != inPublicKey.n.data[i]) return false;
        }

        return true;
    }

    public isCertificateKeyPair(c: CertificateUtil): boolean {
        return this.isIdentical(c.publicKey);
    }

    public async clearCertificateKeyPair(): Promise<OperationResultItem> {
        let currentName = this.absoluteFilename;
        this._row.pairId = null;
        this._row.pairCN = null;
        this._row.name = 'unknown_key';
        let newName = this.absoluteFilename;
        await rename(currentName, newName);
        return this.update();
    }

    public async setCertificateKeyPair(pairId: number, pairCN: string): Promise<OperationResultItem> {
        let currentName = this.absoluteFilename;
        this._row.pairId = pairId;
        this._row.pairCN = pairCN;
        let newName = this.absoluteFilename;
        await rename(currentName, newName);
        return this.update();
    }

    public get absoluteFilename(): string {
        return Path.join(KeyStores.keyPath, KeyUtil._getKeyFilename(this.name, this.$loki));
    }

    public async writeFile(): Promise<void> {
        await writeFile(this.absoluteFilename, this._pem, { encoding: 'utf8' });
    }

    public async deleteFile(): Promise<boolean> {
        if (await exists(this.absoluteFilename)) {
            await unlink(this.absoluteFilename);
            return true;
        }
        else {
            return false;
        }
    }

    public static getIdFromFileName(name: string): number {
        return parseInt(Path.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }

    public update(): OperationResultItem {
        KeyStores.keyDb.update(this.row);
        return new OperationResultItem(this.type, this.$loki);
    }

    public remove(): OperationResult {
        let result = new OperationResult();
        result.pushDeleted(this.getOperationalResultItem());

        if (this.pairId) {
            let cert = CertificateStores.findOne({ $loki: this.pairId });
            if (!cert) {
                logger.warn(`Could not find certificate with id ${this.pairId}`);
            }
            else {
                result.pushUpdated(cert.updateKeyId(null));
            }
        }

        KeyStores.remove(this.$loki);
        result.pushMessage(`Key ${this.name} removed`, ResultType.Success);
        return result;
    }

    public async getpkiKey(password?: string): Promise<pki.rsa.PrivateKey> {
        return new Promise<pki.rsa.PrivateKey>(async (resolve, reject) => {
            // TODO: Should already have a flag that says it is encrypted
            try {
                let p = await readFile(this.absoluteFilename, { encoding: 'utf8' });
                let msg = pem.decode(p)[0];
                if (msg.type.startsWith('ENCRYPTED')) {
                    if (password) {
                        resolve(pki.decryptRsaPrivateKey(p, password));
                    }
                    else {
                        throw new CertError(400, 'No password provided for encrypted key');
                    }
                }
                else {
                    resolve(pki.privateKeyFromPem(p));
                }
            }
            catch (err) {
                reject(err);
            }
        })
    } 

    public static _getKeyDir(filename: string): string {
        return Path.join(KeyStores.keyPath, filename);
    }

    /**
     * Determines the filename of a key from the database record
     * 
     * @param k key's database record
     * @returns Filename in the form of name_identity.pem
     */
    public static _getKeyFilenameFromRow(k: PrivateKeyRow & LokiObj): string {
        return KeyUtil._getKeyFilename(k.name, k.$loki);
    }

    /**
     * Determines the filename for a key
     * 
     * @param name Name in the key record
     * @param $loki Identity in the key record
     * @returns Filename in the form of name_identity.pem
     */
    public static _getKeyFilename(name: string, $loki: number): string {
        return `${name}_${$loki}.pem`;
    }
}

