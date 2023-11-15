import { jsbn } from 'node-forge';
import { CertTypes } from './CertTypes';

export type PrivateKeyRow = {
    name: string;
    type: CertTypes;
    n: jsbn.BigInteger;
    e: jsbn.BigInteger;
    // pairSerial: string,
    /** $loki of certificate pair */
    pairId: number;
    /** Common name of certificate pair */
    pairCN: string;
    /** Set to true if encrypted */
    encrypted: boolean;
};
