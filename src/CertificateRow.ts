import { CertTypes } from './CertTypes';
import { CertificateSubject } from './CertificateSubject';

export type CertificateRow = {
    name: string;
    type: CertTypes;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    publicKey: any;
    privateKey: string;
    tags: string[];
    signedById: number;
    issuer: CertificateSubject;
    subject: CertificateSubject;
    notBefore: Date;
    notAfter: Date;
    havePrivateKey: boolean;
};
