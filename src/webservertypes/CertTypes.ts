
/**
 * Supported object types
 */
export enum CertTypes {
    /** Self-signed root certificate */
    root, 
    /** Intermediate certificate signed by something else but can sign certificates itself */
    intermediate,
    /** Leaf certificate that cannot sign other certificates */
    leaf,
    /** Private key */
    key,
    /** User account */
    user,
}
