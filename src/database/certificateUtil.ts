import { pki, pem, /*jsbn*/ } from "node-forge";
import { CertTypes } from "../webservertypes/CertTypes";
import { CertificateRow } from "../webservertypes/CertificateRow";
import { CertificateSubject } from "../webservertypes/CertificateSubject";
// import { WebServer } from "../webserver";
import { CertificateStores } from "./certificateStores";
import { CertError } from "../webservertypes/CertError";

import Path from "path";
import { unlink, writeFile } from "fs/promises";
import * as log4js from "log4js";
import { readFile, /*writeFile, unlink, rename*/ } from 'fs/promises'
import crypto from 'crypto';
import { OperationResultItem } from "../webservertypes/OperationResultItem";
import { OperationResult } from "../webservertypes/OperationResult";
import { exists } from "../utility/exists";
import { KeyStores } from "./keyStores";
import { KeyUtil } from "./keyUtil";
// import { KeyValueStore } from "lokijs";
// import { KeyStores } from "./keyStores";
// import { PrivateKeyRow } from "../webservertypes/PrivateKeyRow";
// import { KeyStores } from "./keyStores";
// import { KeyUtil } from "./keyUtil";
// import { jsbn, pki, pem, util, random, md } from 'node-forge'; 

const logger = log4js.getLogger();

export class CertificateUtil implements CertificateRow, LokiObj {
    private _row: CertificateRow & LokiObj;
    private _pem: string = null;

    /**
     * Get a CertificateUtil from a PEM string
     * 
     * @param pemString Certificate in PEM format
     * @returns CertificateUtil representing that input PEM file
     */
    public static async createFromPem(pemString: string): Promise<CertificateUtil> {
        let msg = pem.decode(pemString)[0];
        logger.debug(`Received ${msg.type}`);

        if (msg.type != 'CERTIFICATE') {
            throw new CertError(400, 'Unsupported type ' + msg.type);
        }

        let c: pki.Certificate = pki.certificateFromPem(pemString);
        let r: CertificateRow & LokiObj = await CertificateUtil._createRow(c, pemString);

        return new CertificateUtil(r, pemString);
    }
    
    /**
     * Get a CertificateUtil from a pki.certificate
     * 
     * @param c Certificate in pki.certificate format
     * @returns CertificateUtil representing the input pki.Certificate
     */
    public static async createFrompkiCertificate(c: pki.Certificate): Promise<CertificateUtil> {
        let p = pki.certificateToPem(c);
        let r: CertificateRow & LokiObj = await CertificateUtil._createRow(c, p);

        return new CertificateUtil(r, p);
    }

    /**
     * Create a database row
     * 
     * @param c Certficate in pki.Certificate format
     * @param pem The same certificate in PEM format
     * @returns Row ready to write to the database
     */
    private static async _createRow(c: pki.Certificate, pem: string): Promise<CertificateRow & LokiObj> {
        let r: CertificateRow & LokiObj = {
            name: CertificateUtil._sanitizeName(c.subject.getField('CN').value),
            type: await CertificateUtil._calcCertType(c),
            serialNumber: c.serialNumber,
            fingerprint: new crypto.X509Certificate(pem).fingerprint,
            fingerprint256: new crypto.X509Certificate(pem).fingerprint,
            publicKey: c.publicKey,
            tags: [],
            issuer: CertificateUtil._getFields(c.issuer),
            subject: CertificateUtil._getFields(c.subject),
            notBefore: c.validity.notBefore,
            notAfter: c.validity.notAfter,
            signedById: await (CertificateUtil._findSigner(c)),
            keyId: null,
            $loki: undefined,
            meta: {
                created: null,
                revision: null,
                updated: null,
                version: null
            }
        }

        return r;
    }

    /**
     * Construct a CertificateUtl instance from a database row
     * 
     * @param row Database row
     * @param pem Optional PEM version of above
     */
    public constructor(row: CertificateRow & LokiObj, pem?: string) {
        if (row == null) { throw new Error("Certificate row is required to construct this object"); }
        this._row = row;
        if (pem) this._pem = pem;
    }
    
    /** Returns the database row representation */
    public get row(): CertificateRow & LokiObj { return this._row }
    /** A sanitized version of the common name suitable to use as a filename (no blanks etc.) */
    public get name(): string { return this.row.name }
    /** The certificate type - root, intermediate, or leaf */
    public get type(): CertTypes { return this.row.type }
    /** The certificate's serial number */
    public get serialNumber(): string { return this.row.serialNumber }
    /** The SHA1 fingerprint of the certificate */
    public get fingerprint(): string { return this.row.fingerprint }
    /** The SHA256 fingerprint of the certificate */
    public get fingerprint256(): string { return this.row.fingerprint256 }
    /** Public key */
    public get publicKey(): any { return this.row.publicKey }
    /** List of user defined tags */
    public get tags(): string[] { return this.row.tags }
    /** The $loki value of the certificate that signed this one or null if there isn't one in the system */
    public get signedById(): number { return this.row.signedById }
    /** The issuer's certificate subject */
    public get issuer(): CertificateSubject { return this.row.issuer }
    /** This certificate's subject */
    public get subject(): CertificateSubject { return this.row.subject }
    /** The date that this certificate is valid from */
    public get notBefore(): Date { return this.row.notBefore }
    /** The data that this certificate is valid to */
    public get notAfter(): Date { return this.row.notAfter }
    /** $loki value of key pair */
    public get keyId(): number { return this.row.keyId }

    /** LokiObj fields */
    public get $loki(): number { return this.row.$loki }
    /** Loki metadata */
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

    public async insert(): Promise<OperationResult> {
        if (CertificateStores.findOne({ fingerprint256: this.fingerprint256}) != null) {
            throw new CertError(409, `${this.name} already exists (fingerprint256: ${this.fingerprint256}) - ignored`);
        }
        let inserted = CertificateStores.CertificateDb.insertOne(this._row);

        let updates: OperationResultItem[] = [];

        if (this.type == CertTypes.root) {
            updates.push(this.updateSignedById(this.$loki));
        }

        // Look for a private key
        let kRows: KeyUtil[] = KeyStores.find({ pairId: null });

        for (let k of kRows) {
            if (k.isCertificateKeyPair(this)) {
                updates.push(await k.setCertificateKeyPair(this.$loki, this.subject.CN));
                break;
            }
        }

        // Look for certificates signed by this one
        if (this.type != CertTypes.leaf) {
            let cRows = CertificateStores.find({
                $and: [
                    { signedById: { $eq: null } },
                    { $loki: { $ne: this.$loki } },
                    { type: { $in: [CertTypes.leaf, CertTypes.intermediate] } }
                ]
            });

            let cpki = await this.getpkiCert();

            for (let c of cRows) {
                logger.debug(`Checking ${c.name}`);
                try {
                    if (cpki.verify(await c.getpkiCert())) {
                        updates.push(c.updateSignedById(this.$loki));
                        logger.debug(`Marked ${c.name} as signed by ${this.name}`);
                    }
                }
                catch (err) {
                    if (err.message != 'The parent certificate did not issue the given child certificate; the child certificate\'s issuer does not match the parent\'s subject.') {
                        logger.debug('Verify correct error: ' + err.message);
                    }
                }
            }
        }
        
        return new OperationResult(inserted.name)
            .pushAdded(new OperationResultItem(inserted.type, inserted.$loki))
            .pushUpdated(updates)
    }

    public updateKeyId(id: number): OperationResultItem {
        this._row.keyId = id;
        return this.update();
    }

    public updateSignedById(id: number): OperationResultItem {
        this._row.signedById = id;
        return this.update()
    }

    public update(): OperationResultItem {
        CertificateStores.CertificateDb.update(this.row);
        return this.getOperationalResultItem();
    }

    public async remove(): Promise<OperationResult> {
        let result: OperationResult = new OperationResult('');
        result.pushDeleted(this.getOperationalResultItem())

        let key = KeyStores.findOne({ $loki: this.keyId });

        if (key) {
            result.pushUpdated(await key.clearCertificateKeyPair());
        }

        CertificateStores.bulkUpdate({ $and: [{ signedById: this.$loki }, { $loki: { $ne: this.$loki } }] }, (cert) => {
            cert.signedById = null;
            result.pushUpdated(new OperationResultItem(cert.type, cert.$loki));
        });

        CertificateStores.CertificateDb.remove(this.row);

        return result;
    }

    public get absoluteFilename(): string {
        return Path.join(CertificateStores.CertificatePath, CertificateUtil._getKeyFilename(this.name, this.$loki));
    }

    public async writeFile(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            try {
                if (!this._pem) {
                    // This would typically mean that the file already exists
                    throw new Error("Logic error: pem is not available to write");
                }
                writeFile(this.absoluteFilename, this._pem, { encoding: 'utf8' });
                resolve();
            }
            catch (err) {
                reject(err);
            }
        })
        writeFile(this.absoluteFilename, this._pem)
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

    public async getpkiCert(): Promise<pki.Certificate> {
        return pki.certificateFromPem(this._pem? this._pem : await readFile(this.absoluteFilename, { encoding: 'utf8'}));
    }

    public isKeyPair(key: KeyUtil) {
        return key.isIdentical(this.publicKey as pki.rsa.PublicKey);
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

    private static _sanitizeName(name: string) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }

    private static _getFields(s: pki.Certificate['issuer'] | pki.Certificate['subject']): CertificateSubject {
        let getValue: (v: string) => string = (v: string): string => {
            let work = s.getField(v);
            return work ? work.value : null;
        }
        return {
            C: getValue('C'),
            ST: getValue('ST'),
            L: getValue('L'),
            O: getValue('O'),
            OU: getValue('OU'),
            CN: getValue('CN')
        }
    }

    private static async _calcCertType(c: pki.Certificate): Promise<CertTypes> {
        let type: CertTypes;
        // let signedById: number;

        if (c.isIssuer(c)) {
            type = CertTypes.root;
            // signedById = -1;
        }
        else {
            let bc: any = c.getExtension('basicConstraints');

            if ((bc != null) && (bc.cA ?? false) == true && (bc.pathlenConstraint ?? 1) > 0) {
                type = CertTypes.intermediate;
            }
            else {
                type = CertTypes.leaf;
            }

            // See if any existing certificates signed this one
            // let signer = await CertificateUtil._findSigner(c);

            // if (signer != null) {
            //     // signedById = signer.$loki;
            // }
        }

        return type;
    }

    private static async _findSigner(c: pki.Certificate): Promise<number> {
        return new Promise<number>(async (resolve, _reject) => {
            let i;
            let rowList: CertificateUtil[] = CertificateStores.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
            for (i = 0; i < rowList.length; i++) {
                try {
                    let r = await rowList[i].getpkiCert();
                    if (r.verify(c)) {
                        resolve(rowList[i].$loki);
                        break;
                    }
                }
                catch (err) {
                    // TODO Handle other errors than verify error
                    if (!err.actualIssuer || !err.expectedIssuer) {
                        logger.debug(`Possible error: ${err.message}`);
                    }
                    // verify should return false but apparently throws an exception - do nothing
                }
            }

            if (i == rowList.length) {
                resolve(null);
            }
        });
    }

    // private static async _pkiCertFromRow(c: CertificateUtil): Promise<pki.Certificate> {
    //     return new Promise<pki.Certificate>(async (resolve, reject) => {
    //         try {
    //             resolve(pki.certificateFromPem(await readFile(c.absoluteFilename, { encoding: 'utf8' })));
    //         }
    //         catch (err) {
    //             reject(err);
    //         }
    //     });
    // }

    // private static _getCertificateDir(filename: string): string {
    //     return Path.join(CertificateStores.CertificatePath, filename);
    // }

    // private static _getCertificateFilenameFromRow(c: CertificateUtil): string {
    //     return `${c.name}_${c.$loki}.pem`;
    // }

    // /**
    //  * Tests a certificate and key to determine if they are a pair
    //  * 
    //  * @param cert Certificate in node-forge pki format
    //  * @param keyn Key n big integer
    //  * @param keye Key e big integer
    //  * @returns true if this is the key paired with the certificate
    //  */
    // private static _isKeyPair(cert: pki.Certificate, keyn: jsbn.BigInteger, keye: jsbn.BigInteger): boolean {
    //     let publicKey = pki.setRsaPublicKey(keyn, keye);
    //     let certPublicKey: pki.rsa.PublicKey = cert.publicKey as pki.rsa.PublicKey;

    //     return this._isIdenticalKey(publicKey, certPublicKey);
    // }

    // /**
    //  * Compares to keys for equality
    //  * 
    //  * @param leftKey First key to compare
    //  * @param rightKey Second key to compare
    //  * @returns true if the keys are identical
    //  */
    // private static _isIdenticalKey(leftKey: pki.rsa.PublicKey, rightKey: pki.rsa.PublicKey): boolean {
    //     if (leftKey.n.data.length != rightKey.n.data.length) {
    //         return false;
    //     }

    //     for (let i = 0; i < leftKey.n.data.length; i++) {
    //         if (leftKey.n.data[i] != rightKey.n.data[i]) return false;
    //     }

    //     return true;
    // }
}