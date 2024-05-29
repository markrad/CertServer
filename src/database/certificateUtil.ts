import { pki, pem, util, random, md, /*jsbn*/ } from "node-forge";
import { CertTypes } from "../webservertypes/CertTypes";
import { CertificateRow } from "../webservertypes/CertificateRow";
import { CertificateSubject } from "../webservertypes/CertificateSubject";
import { CertificateStores } from "./certificateStores";
import { CertError } from "../webservertypes/CertError";

import Path from "path";
import { unlink, writeFile } from "fs/promises";
import * as log4js from "log4js";
import { readFile, /*writeFile, unlink, rename*/ } from 'fs/promises'
import crypto from 'crypto';
import { OperationResultItem } from "../webservertypes/OperationResultItem";
import { OperationResult, ResultMessage, ResultType } from "../webservertypes/OperationResult";
import { exists } from "../utility/exists";
import { KeyStores } from "./keyStores";
import { KeyUtil } from "./keyUtil";
import { CertificateBrief } from "../webservertypes/CertificateBrief";
import { GenerateCertRequest } from "../webservertypes/GenerateCertRequest";
import { CertificateInput } from "../webservertypes/CertificateInput";
import { ExtensionParent } from "../extensions/ExtensionParent";
import { ExtensionBasicConstraints } from "../extensions/ExtensionBasicConstraints";
import { ExtensionKeyUsage } from "../extensions/ExtensionKeyUsage";
import { ExtensionSubjectKeyIdentifier } from "../extensions/ExtensionSubjectKeyIdentifier";
import { ExtensionAuthorityKeyIdentifier } from "../extensions/ExtensionAuthorityKeyIdentifier";
import { ExtensionExtKeyUsage } from "../extensions/ExtensionExtKeyUsage";
import { ExtensionSubjectAltName /*, ExtensionSubjectAltNameOptions */} from "../extensions/ExtensionSubjectAltName";

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
            signedById: ((await CertificateUtil._findSigner(c))?.$loki ?? null),
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

    /**
     * Updates the key ID of the certificate.
     * 
     * @param id - The new key ID to be set.
     * @returns An `OperationResultItem` representing the result of the update operation.
     */
    public updateKeyId(id: number): OperationResultItem {
        this._row.keyId = id;
        return this.update();
    }

    /**
     * Updates the signedById property of the certificateUtil instance.
     * 
     * @param id - The ID of the certificate that signed this certificate.
     * @returns An OperationResultItem indicating the result of the update operation.
     */
    public updateSignedById(id: number): OperationResultItem {
        this._row.signedById = id;
        return this.update()
    }

    /**
     * Updates the tags of the certificate.
     * @param tags - An array of strings representing the new tags for the certificate.
     * @returns An OperationResultItem object representing the result of the update operation.
     */
    public updateTags(tags: string[]): OperationResultItem {
        this._row.tags = tags;
        return this.update();
    }

    /**
     * Updates the certificate in the certificate database.
     * 
     * @returns {OperationResultItem} The operation result item.
     */
    public update(): OperationResultItem {
        CertificateStores.CertificateDb.update(this.row);
        return this.getOperationalResultItem();
    }

    /**
     * Removes the certificate from the database.
     * @returns A Promise that resolves to an OperationResult indicating the success of the removal operation.
     */
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
        result.pushMessage(`Certificate ${this.name} removed`, ResultType.Success);

        return result;
    }

    /**
     * Returns a brief representation of the certificate required for display on the web interface.
     * @returns {CertificateBrief} The brief representation of the certificate.
     */
    public certificateBrief(): CertificateBrief {
        let c: CertificateUtil = null;

        if (this.signedById != null) {
            c = CertificateStores.findOne({ $loki: this.signedById });
            if (c == null) {
                logger.warn(`Signing certificate missing for ${c.name}`);
            }
        }

        let s: number[] = CertificateStores.find({ signedById: this.$loki }).map((r) => r.$loki);

        return {
            id: this.$loki,
            certType: CertTypes[this.type],
            name: this.subject.CN,
            issuer: this.issuer,
            subject: this.subject,
            validFrom: this.notBefore,
            validTo: this.notAfter,
            serialNumber: this.serialNumber == null ? '' : this.serialNumber.match(/.{1,2}/g).join(':'),  // Hacky fix for dud entries in db
            signer: c ? c.subject.CN : null,
            signerId: c ? c.$loki : null,
            keyId: this.keyId,
            fingerprint: this.fingerprint,
            fingerprint256: this.fingerprint256,
            signed: s,
            tags: this.tags ?? [],
        };
    }

    /**
     * Retrieves the certificate chain by reading the contents of each certificate file.
     * The chain is constructed by starting from the current certificate and following the `signedById` property.
     * Each certificate file is read using the `readFile` function with 'utf8' encoding.
     * 
     * @returns A Promise that resolves to a string representing the concatenated contents of all the certificate files in the chain.
     * @throws {CertError} If a certificate row with the specified `signedById` is not found in the database.
     */
    public async getCertificateChain(): Promise<string> {
        return new Promise<string>(async (resolve, reject) => {
            try {
                let file: string;

                file = await readFile(this.absoluteFilename, { encoding: 'utf8' });

                let s = this.signedById;

                while (s != null) {
                    let c = CertificateStores.findOne({ $loki: s });

                    if (c == null) {
                        throw new CertError(500, `Expected certificate row with id ${s}`);
                    }

                    file += await readFile(c.absoluteFilename, { encoding: 'utf8' });
                    s = c.signedById == c.$loki? null : c.signedById;
                }

                resolve(file);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Gets the absolute filename of the certificate.
     * The absolute filename is determined by joining the certificate path with the key filename.
     * @returns The absolute filename of the certificate.
     */
    public get absoluteFilename(): string {
        return Path.join(CertificateStores.CertificatePath, CertificateUtil._getKeyFilename(this.name, this.$loki));
    }

    /**
     * Writes the PEM content to a file.
     * @returns A Promise that resolves when the file is successfully written, or rejects with an error if there was a problem.
     */
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

    /**
     * Deletes the file associated with this certificate.
     * 
     * @returns A promise that resolves to `true` if the file is successfully deleted, or `false` if the file does not exist.
     */
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
     * Retrieves the PKI certificate.
     * If the certificate is already available in memory, it returns it.
     * Otherwise, it reads the certificate from the file system and returns it.
     * @returns A Promise that resolves to the PKI certificate.
     */
    public async getpkiCert(): Promise<pki.Certificate> {
        return pki.certificateFromPem(this._pem? this._pem : await readFile(this.absoluteFilename, { encoding: 'utf8'}));
    }

    /**
     * Finds the signer of the certificate.
     * @returns A Promise that resolves to a CertificateUtil instance representing the signer.
     */
    public async findSigner(): Promise<CertificateUtil> {
        return CertificateUtil._findSigner(await this.getpkiCert());
    }

    /**
     * Checks if the given key is a key pair.
     * @param key - The key to check.
     * @returns True if the key is a key pair, false otherwise.
     */
    public isKeyPair(key: KeyUtil) {
        return key.isIdentical(this.publicKey as pki.rsa.PublicKey);
    }

    /**
     * Generates a certificate pair consisting of a certificate and a private key.
     * 
     * @param type - The type of certificate to generate.
     * @param body - The input data for generating the certificate.
     * @returns A promise that resolves to an object containing the generated certificate PEM, key PEM, and the result of the operation.
     * @throws {CertError} If an error occurs during the generation process.
     */
    public static async generateCertificatePair(type: CertTypes, body: any): Promise<{ certificatePem: string, keyPem: string, result: OperationResult }> {
        return new Promise<{ certificatePem: string, keyPem: string, result: OperationResult }>(async (resolve, reject) => {
            try {
                let result: OperationResult = new OperationResult('');
                let { certificateInput, messages } = CertificateUtil._validateCertificateInput(type, body);
                if (messages.hasErrors) {
                    resolve({ certificatePem: null, keyPem: null, result: messages });
                    return;
                }

                const cRow: CertificateUtil = type == CertTypes.root ? null : CertificateStores.findOne({ $loki: parseInt(certificateInput.signer) });
                const kRow: KeyUtil = type == CertTypes.root ? null : KeyStores.findOne({ $loki: cRow.keyId });

                if (type != CertTypes.root && (!cRow || !kRow)) {
                    resolve({ certificatePem: null, keyPem: null, result: result.pushMessage('Signing certificate or key are either missing or invalid', ResultType.Failed) });
                    return;
                }

                const c: pki.Certificate = type == CertTypes.root ? null : await cRow.getpkiCert();
                const k: pki.PrivateKey = type == CertTypes.root ? null : await kRow.getpkiKey(certificateInput.password);
                const { privateKey, publicKey } = pki.rsa.generateKeyPair(2048);
                const attributes = CertificateUtil._setAttributes(certificateInput.subject);
                const extensions: ExtensionParent[] = [];

                if (type != CertTypes.leaf) {
                    extensions.push(new ExtensionBasicConstraints({ cA: true, critical: true }));
                    extensions.push(new ExtensionKeyUsage({ keyCertSign: true, cRLSign: true }));
                }

                if (type != CertTypes.root) {
                    extensions.push(new ExtensionAuthorityKeyIdentifier({ keyIdentifier: c.generateSubjectKeyIdentifier().getBytes(), authorityCertSerialNumber: true }));
                }

                if (type == CertTypes.leaf) {
                    extensions.push(new ExtensionBasicConstraints({ cA: false }));
                    extensions.push(new ExtensionKeyUsage({ nonRepudiation: true, digitalSignature: true, keyEncipherment: true }));
                    extensions.push(new ExtensionExtKeyUsage({ serverAuth: true, clientAuth: true, }));
                    extensions.push(new ExtensionSubjectAltName(certificateInput.san));
                }

                extensions.push(new ExtensionSubjectKeyIdentifier({}));

                // Create an empty Certificate
                let cert = pki.createCertificate();
                cert.publicKey = publicKey;
                // cert.privateKey = privateKey;
                cert.serialNumber = CertificateUtil._getRandomSerialNumber();
                cert.validity.notBefore = certificateInput.validFrom;
                cert.validity.notAfter = certificateInput.validTo;
                cert.setSubject(attributes);
                cert.setIssuer(type == CertTypes.root ? attributes : c.subject.attributes);
                cert.setExtensions(extensions.map((extension) => extension.getObject()));

                // Self-sign root but use the signer's key for the others
                cert.sign(type == CertTypes.root ? privateKey : k, md.sha512.create());
                resolve({ certificatePem: pki.certificateToPem(cert), keyPem: pki.privateKeyToPem(privateKey), result: result });
            }
            catch (err) {
                reject(new CertError(500, err.message));
            }
        });
    }

    /**
     * Extracts the ID from a given file name.
     * 
     * @param name - The file name from which to extract the ID.
     * @returns The extracted ID as a number.
     */
    public static getIdFromFileName(name: string): number {
        return parseInt(Path.parse(name).name.split('_').slice(-1)[0].split('.')[0]);
    }

    /**
     * Determines the filename for a key
     * 
     * @param name Name in the key record
     * @param $loki Identity in the key record
     * @returns Filename in the form of name_identity.pem
     */
    private static _getKeyFilename(name: string, $loki: number): string {
        return `${name}_${$loki}.pem`;
    }

    /**
     * Sanitizes the given name by replacing any characters that are not alphanumeric, underscore, hyphen, equal sign, plus sign, curly braces, square brackets, parentheses, double quotes, or single quotes with an underscore.
     * 
     * @param name - The name to be sanitized.
     * @returns The sanitized name.
     */
    private static _sanitizeName(name: string) {
        return name.replace(/[^\w-_=+{}\[\]\(\)"'\]]/g, '_');
    }

    /**
     * Retrieves the fields from the issuer or subject of a certificate.
     * 
     * @param s - The issuer or subject of a certificate.
     * @returns An object containing the values of the fields.
     */
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

    /**
     * Calculates the type of the certificate.
     * @param c - The certificate to calculate the type for.
     * @returns A promise that resolves to the type of the certificate.
     */
    private static async _calcCertType(c: pki.Certificate): Promise<CertTypes> {
        let type: CertTypes = null;
        // let signedById: number;

        try {
            c.verify(c);
            type = CertTypes.root;
        }
        catch (_err) {
            // Don't care - verify throws an error rather than returning a boolean
        }
        // if (c.verify(c)) { 
        //     type = CertTypes.root;
        //     // signedById = -1;
        // }
        if (type == null) {
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

    /**
     * Finds the signer certificate for the given certificate.
     * @param c - The certificate for which to find the signer.
     * @returns A Promise that resolves with the signer certificate, or null if not found.
     */
    private static async _findSigner(c: pki.Certificate): Promise<CertificateUtil> {
        return new Promise<CertificateUtil>(async (resolve, _reject) => {
            let i;
            let rowList: CertificateUtil[] = CertificateStores.find({ 'type': { '$in': [CertTypes.root, CertTypes.intermediate] } });
            for (i = 0; i < rowList.length; i++) {
                try {
                    let r = await rowList[i].getpkiCert();
                    if (r.verify(c)) {
                        resolve(rowList[i]);
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

    /**
     * Validates the certificate input and returns the certificate input object and operation result.
     * @param type - The type of certificate.
     * @param bodyIn - The input body containing certificate details.
     * @returns An object containing the certificate input and operation result.
     * @throws {CertError} If there is an error in the certificate input.
     */
    private static _validateCertificateInput(type: CertTypes, bodyIn: any): { certificateInput: CertificateInput, messages: OperationResult } {
        // FUTURE Needs a mechanism to force parts of the RDA sequence to be omitted
        try {
            if (typeof bodyIn !== 'object') {
                throw new CertError(400, 'Bad POST data format - use Content-type: application/json');
            }
            let body: GenerateCertRequest = bodyIn;
            let result: CertificateInput = {
                validFrom: body.validFrom ? new Date(body.validFrom) : new Date(),
                validTo: new Date(body.validTo),
                signer: body.signer ?? null,
                password: body.password ?? null,
                subject: {
                    C: body.country ? body.country : null,
                    ST: body.state ? body.state : null,
                    L: body.location ? body.location : null,
                    O: body.organization ? body.organization : null,
                    OU: body.unit ? body.unit : null,
                    CN: body.commonName ? body.commonName : null
                },
                san: {
                    domains: [],
                    IPs: [],
                }
            };
            let opResults: OperationResult = new OperationResult('Generate Certificate');
            if (!result.subject.CN) opResults.pushMessage('Common name is required' , ResultType.Failed);
            if (!result.validTo) opResults.pushMessage('Valid to is required', ResultType.Failed);
            if (type != CertTypes.root && !body.signer) opResults.pushMessage('Signing certificate is required', ResultType.Failed);
            if (isNaN(result.validTo.valueOf())) opResults.pushMessage('Valid to is invalid', ResultType.Failed);
            if (body.validFrom && isNaN(result.validFrom.valueOf())) opResults.pushMessage('Valid from is invalid', ResultType.Failed);
            if (result.subject.C != null && result.subject.C.length != 2) opResults.pushMessage('Country code must be omitted or have two characters', ResultType.Failed);
            let rc: ResultMessage = CertificateUtil._isValidRNASequence([result.subject.C, result.subject.ST, result.subject.L, result.subject.O, result.subject.OU, result.subject.CN]);
            if (rc) opResults.pushMessage(rc.message, rc.type);
            if (opResults.hasErrors) {
                opResults.setStatusCode(400);
                return { certificateInput: null, messages: opResults };
            }
            if (type == CertTypes.leaf) {
                result.san.domains.push(body.commonName);
            }
            if (type != CertTypes.root && body.SANArray) {
                let SANArray = Array.isArray(body.SANArray) ? body.SANArray : [body.SANArray];
                let domains = SANArray.filter((entry: string) => entry.startsWith('DNS:')).map((entry: string) => entry.split(' ')[1]);
                let ips = SANArray.filter((entry: string) => entry.startsWith('IP:')).map((entry: string) => entry.split(' ')[1]);
                if (domains.length > 0) result.san.domains = result.san.domains.concat(domains);
                if (ips.length > 0) result.san.IPs = ips;
            }
            return { certificateInput: result, messages: opResults };
        }
        catch (err) {
            throw new CertError(500, err.message);
        }
    }

    /**
     * Validates RNA strings to ensure they consist only of characters allowed in those strings. The node-forge package does not enforce this.
     * 
     * @param rnas Array of RNA values for validation
     * @returns {{valid: boolean, message?: string}} valid: true if all are valid otherwise valid: false, message: error message
     */
    private static _isValidRNASequence(rnas: string[]): ResultMessage {
        for (let r in rnas) {
            if (!/^[a-z A-Z 0-9'\=\(\)\+\,\-\.\/\:\?]*$/.test(rnas[r])) {
                return { message: 'Subject contains an invalid character', type: ResultType.Failed };
            }
        }
        return null;
    }

    /**
     * Generates a certificate serial number
     * 
     * @returns A random number to use as a certificate serial number
     */
    private static _getRandomSerialNumber(): string {
        return CertificateUtil._makeNumberPositive(util.bytesToHex(random.getBytesSync(20)));
    }

    /**
     * If the passed number is negative it is made positive
     * 
     * @param hexString String containing a hexadecimal number
     * @returns Positive version of the input
     */
    private static _makeNumberPositive = (hexString: string): string => {
        let mostSignificativeHexDigitAsInt = parseInt(hexString[0], 16);

        if (mostSignificativeHexDigitAsInt < 8)
            return hexString;

        mostSignificativeHexDigitAsInt -= 8;
        return mostSignificativeHexDigitAsInt.toString() + hexString.substring(1);
    };

    /**
     * Add subject values to pki.CertificateField
     * 
     * @param subject Subject fields for the certificate
     * @returns pki.CertificateField with the provided fields
     */
    private static _setAttributes(subject: CertificateSubject): pki.CertificateField[] {
        let attributes: pki.CertificateField[] = [];
        if (subject.C)
            attributes.push({ shortName: 'C', value: subject.C });
        if (subject.ST)
            attributes.push({ shortName: 'ST', value: subject.ST });
        if (subject.L)
            attributes.push({ shortName: 'L', value: subject.L });
        if (subject.O)
            attributes.push({ shortName: 'O', value: subject.O });
        if (subject.OU)
            attributes.push({ shortName: 'OU', value: subject.OU });
        attributes.push({ shortName: 'CN', value: subject.CN });

        return attributes;
    }
}