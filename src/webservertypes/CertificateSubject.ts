/**
 * Represents a certificate subject
 */
export type CertificateSubject = {
    /** Country - must be two characters */
    C?: string;
    /** State or province */
    ST?: string;
    /** Location (city/town) */
    L?: string;
    /** Organization */
    O?: string;
    /** Organizational unit */
    OU?: string;
    /** Common name */
    CN: string;
};
