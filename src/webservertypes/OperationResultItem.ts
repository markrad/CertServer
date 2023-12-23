import { CertTypes } from './CertTypes';

/**
 * Represents a single modification to the database
 */
export type OperationResultItem = {
    /** The type entry modified either a key or a root, intermediate, or leaf certificate */
    type: CertTypes;
    /** The $loki id of the row in the database */
    id: number;
};
