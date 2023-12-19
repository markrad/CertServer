import { CertTypes } from './CertTypes';
import { CertificateSubject } from './CertificateSubject';

/**
 * The LokiDb certificate row definition
 */
export type CertificateRow = {
    /** A sanitized version of the common name suitable to use as a filename (no blanks etc.) */
    name: string;
    /** The certificate type - root, intermediate, or leaf */
    type: CertTypes;
    /** The certificate's serial number */
    serialNumber: string;
    /** The SHA1 fingerprint of the certificate */
    fingerprint: string;
    /** The SHA256 fingerprint of the certificate */
    fingerprint256: string;
    /** Public key */
    publicKey: any;
    // TODO Deprecate this
    /** Not used - will be deprecated */
    privateKey: string;
    /** List of user defined tags */
    tags: string[];
    /** The $loki value of the certificate that signed this one or null if there isn't one in the system */
    signedById: number;
    /** The issuer's certificate subject */
    issuer: CertificateSubject;
    /** This certificate's subject */
    subject: CertificateSubject;
    /** The date that this certificate is valid from */
    notBefore: Date;
    /** The data that this certificate is valid to */
    notAfter: Date;
    // TODO - Deprecate this
    /** Not used - will be deprecated */
    havePrivateKey: boolean;
    /** $loki value of key pair */
    keyId: number;
};
