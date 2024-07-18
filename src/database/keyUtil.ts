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
import { KeyEncryption } from "./keyEncryption";
import { DbStores } from "./dbStores";

let logger = log4js.getLogger();

export class KeyUtil implements PrivateKeyRow, LokiObj {
    private _row: PrivateKeyRow & LokiObj;
    private _pem: string = null;

    /**
     * Creates a KeyUtil instance from a PEM string.
     * 
     * @param pemString - The PEM string representing the key.
     * @param password - The password to decrypt the encrypted private key (optional).
     * @returns A Promise that resolves to a KeyUtil instance.
     * @throws CertError if the key is encrypted and no password is provided.
     */
    public static async CreateFromPem(pemString: string, password?: string): Promise<KeyUtil> {
        let k: pki.rsa.PrivateKey;
        let r: PrivateKeyRow & LokiObj;
        let msg = pem.decode(pemString)[0];
        let encrypted: KeyEncryption = KeyEncryption.NONE;
        if (msg.type == 'ENCRYPTED PRIVATE KEY') {
            if (!password) {
                logger.warn(`Encrypted key requires password`);
                throw(new CertError(400, 'Password is required for key'));
            }
            k = pki.decryptRsaPrivateKey(pemString, password);
            encrypted = password != KeyStores.keySecret? KeyEncryption.USER : KeyEncryption.SYSTEM;
        }
        else {
            k = pki.privateKeyFromPem(pemString);
            if (DbStores.getKeyEncryptionState()) {
                pemString = pki.encryptRsaPrivateKey(k, KeyStores.keySecret);
                encrypted = KeyEncryption.SYSTEM;
            }
        }

        r = KeyUtil._createRow(k, encrypted);
        
        return new KeyUtil(r, pemString);
    }

    /**
     * Creates a private key row object.
     * @param k - The RSA private key.
     * @param encryptedType - The type of key encryption.
     * @returns The private key row object.
     */
    private static _createRow(k: pki.rsa.PrivateKey, encryptedType: KeyEncryption): PrivateKeyRow & LokiObj {
        return {
            e: k.e,
            n: k.n,
            pairId: null,
            pairCN: null,
            name: null,
            type: CertTypes.key,
            encrypted: undefined,
            encryptedType: encryptedType,
            $loki: undefined,
            meta: {
                created: null,
                revision: null,
                updated: null,
                version: null
            }
        }
    }

    /**
     * Creates a KeyUtil object from a database row.
     * @constructor
     * @param row - The database row representing the key.
     * @param pem - The PEM string representing the key (optional).
     */
    public constructor(row: PrivateKeyRow & LokiObj, pem?: string) {
        if (row == null) { throw new Error("Key row is required to construct this object"); }
        this._row = row;
        this._pem = pem || null;
    }

    public get row(): PrivateKeyRow & LokiObj { return this._row; }
    public get e(): jsbn.BigInteger { return this.row.e; }
    public get n(): jsbn.BigInteger { return this.row.n; }
    public get pairId(): number { return this.row.pairId; }
    public get pairCN(): string { return this.row.pairCN; }
    public get name(): string { return this.row.name; }
    public get type(): CertTypes { return this.row.type; }
    public get encrypted(): boolean { return this.row.encryptedType != KeyEncryption.NONE; }
    public get encryptedType(): KeyEncryption { return this.row.encryptedType; }

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

    /**
     * Generates an operational result item from this instance.
     * @returns {OperationResultItem} The operational result item.
     */
    public getOperationalResultItem(): OperationResultItem {
        return new OperationResultItem(this.type, this.$loki);
    }

    /**
     * Returns a brief representation of the key.
     * @returns The key brief object.
     */
    public get keyBrief(): KeyBrief {
        return {
            id: this.$loki,
            name: this.name,
            certPair: (this.pairId == null) ? 'Not present' : this.name.substring(0, this.name.length - 4),
            encrypted: this.encrypted,
        }
    }

    /**
     * Encrypts the private key with the specified password and encryption type.
     * @param password - The password to encrypt the private key.
     * @param encryptedType - The encryption type to use.
     * @returns A promise that resolves to an OperationResultItem.
     */
    public async encrypt(password: string, encryptedType: KeyEncryption): Promise<OperationResultItem> {
        return new Promise<OperationResultItem>(async (resolve, reject) => {
            try {
                if (this.encryptedType != KeyEncryption.NONE) {
                    throw new CertError(400, 'Key is already encrypted');
                }
                let pem = this._pem? this._pem : await this.readFile();
                let k = pki.privateKeyFromPem(pem);
                this._pem = pki.encryptRsaPrivateKey(k, password);
                await this.deleteFile();
                await this.writeFile();
                this._row.encryptedType = encryptedType;
                this._row.encrypted = undefined;
                resolve(this.update());
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Decrypts the private key using the provided password.
     * @param password - The password used for decryption.
     * @returns A Promise that resolves to an OperationResultItem.
     * @throws CertError if the key is not encrypted.
     */
    public async decrypt(password: string): Promise<OperationResultItem> {
        return new Promise<OperationResultItem>(async (resolve, reject) => {
            try {
                if (this.encryptedType == KeyEncryption.NONE) {
                    throw new CertError(400, 'Key is not encrypted');
                }
                let pem = this._pem? this._pem : await this.readFile();
                let k = pki.decryptRsaPrivateKey(pem, password);
                this._pem = pki.privateKeyToPem(k);
                await this.deleteFile();
                await this.writeFile();
                this._row.encryptedType = KeyEncryption.NONE;
                this._row.encrypted = undefined;
                resolve(this.update());
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Inserts a new key into the key database.
     * 
     * @returns An OperationResult object representing the result of the insertion.
     */
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

        if (this._row.name == null) {
            this._row.name = 'unknown_key';
        }
        KeyStores.keyDb.insert(this._row);
        result.pushAdded(this.getOperationalResultItem());

        if (certPair) {
            result.pushUpdated(certPair.updateKeyId(this.$loki));
        }

        return result;
    }

    /**
     * Sets the RSA public key.
     * @returns The RSA public key.
     */
    public setRsaPublicKey(): pki.rsa.PublicKey {
        return pki.setRsaPublicKey(this.n, this.e);
    }

    /**
     * Checks if the provided public key is identical to the current instance's public key.
     * @param inPublicKey - The public key to compare.
     * @returns `true` if the public keys are identical, `false` otherwise.
     */
    public isIdentical(inPublicKey: pki.rsa.PublicKey | KeyUtil): boolean {
        let myPublicKey = this.setRsaPublicKey();

        if (inPublicKey instanceof KeyUtil) {
            inPublicKey = inPublicKey.setRsaPublicKey();
        }

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
        return new Promise<void>(async (resolve, reject) => {
            try {
                if (!this._pem) throw new Error('No PEM data to write');                    // This should not happen
                await writeFile(this.absoluteFilename, this._pem, { encoding: 'utf8' });
                resolve();
            }
            catch (err) {
                reject(err);
            }
        });
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

    /**
        * Reads the contents of the associated pem file and returns it as a string.
        * @returns A promise that resolves with the contents of the file as a string.
        */
    public async readFile(): Promise<string> {
        return await readFile(this.absoluteFilename, { encoding: 'utf8' });
    }

    public static getIdFromFileName(name: string): number {
        return parseInt(Path.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }

    /**
     * Decodes a PEM string and returns an array of PEM objects.
     * @param pemString The PEM string to decode.
     * @returns An array of PEM objects.
     */
    public static pemDecode(pemString: string): pem.ObjectPEM[] {
        return pem.decode(pemString);
    }

    /**
     * Encodes a PEM object into a string.
     * @param pemObject The PEM object to encode.
     * @returns The encoded PEM object as a string.
     */
    public static pemEncode(pemObject: pem.ObjectPEM): string {
        return pem.encode(pemObject, { maxline: 64 });
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
            try {
                let p = await readFile(this.absoluteFilename, { encoding: 'utf8' });
                switch (this.encryptedType) {
                    case KeyEncryption.SYSTEM:
                        resolve(pki.decryptRsaPrivateKey(p, KeyStores.keySecret));
                        break;
                    case KeyEncryption.USER:
                        if (!password) {
                            throw new CertError(400, 'Password required for encrypted key');
                        }
                        resolve(pki.decryptRsaPrivateKey(p, password));
                        break;
                    default:
                        resolve(pki.privateKeyFromPem(p));
                        break;
                }
                if (this.encryptedType == KeyEncryption.USER && !password) {
                    throw new CertError(400, 'Password required for encrypted key');
                }
            }
            catch (err) {
                reject(err);
            }
        })
    }

    public async getPemString(): Promise<string> {
        return new Promise<string>(async (resolve, reject) => {
            try {
                if (this.encryptedType != KeyEncryption.SYSTEM) {
                    resolve(await this.readFile());
                }
                else {
                    let k = await this.getpkiKey();
                    resolve(pki.privateKeyToPem(k));
                }
            }
            catch (err) {
                reject(err);
            }
        });
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

