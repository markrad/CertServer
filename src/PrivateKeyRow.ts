import { jsbn } from 'node-forge';
import { CertTypes } from './CertTypes';

export type PrivateKeyRow = {
    name: string;
    type: CertTypes;
    n: jsbn.BigInteger;
    e: jsbn.BigInteger;
    // pairSerial: string,
    pairId: number;
    pairCN: string;
    encrypted: boolean;
};
