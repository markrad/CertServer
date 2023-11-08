import { CertificateSubject } from './CertificateSubject';

export type CertificateBrief = {
    id: number;
    certType: string;
    name: string;
    issuer: CertificateSubject;
    subject: CertificateSubject;
    validFrom: Date;
    validTo: Date;
    signer: string;
    signerId: number;
    keyPresent: string;
    keyId: number;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    signed: number[];
    tags: string[];
};
