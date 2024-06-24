/**
 * Represents the database row that contains the database version number. There should only ever be one of these rows.
 */
export type DBVersionRow = {
    /** Database version number */
    version: number;
    /** The secret key used to encrypt the private keys */
    keySecret: string;
    /** The secret used to hash passwords */
    passwordSecret: string;
    /** Is true if keys are being encrypted */
    keyEncryptionState: boolean;
    /** if true is authentication is being used */
    authenticationState: boolean;
};
