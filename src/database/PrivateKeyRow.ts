import { jsbn } from 'node-forge';
import { CertTypes } from '../webservertypes/CertTypes';
import { KeyEncryption } from './keyEncryption';

/**
 * Data structure for the keys in the database
 */
/**
 * Represents a private key row in the database.
 */
export interface PrivateKeyRow {
    /** CN from the certificate otherwise 'unknown_key' - used with the $loki to generate the filename */
    name: string;
    /** Will always have the value CertTypes.key - may get deprecated */
    type: CertTypes;
    /** n value from node-forge pki.rsa.PrivateKey */
    n: jsbn.BigInteger;
    /** e value from node-forge pki.rsa.PrivateKey */
    e: jsbn.BigInteger;
    /** $loki of certificate pair or null if there is no pair */
    pairId: number;
    /** Common name of certificate pair or null if there is no pair */
    pairCN: string;
    /** The type of key encryption */
    encryptedType: KeyEncryption;
}
