import { OperationResultItem } from './OperationResultItem';

/**
 * Used to return database entries that have been added, deleted, or updated.
 *
 * @member name: The common name of the certificate or key - will be deprecated
 * @member added Array of certificates or keys added
 * @member updated Array of certificates or keys updated
 * @member deleted Array of certificates or keys deleted
 */
export type OperationResult = {
    name: string;
    /** Certificates or keys added */
    added: OperationResultItem[];
    /** Certificates or keys updated */
    updated: OperationResultItem[];
    /** Certificates or keys deleted */
    deleted: OperationResultItem[];
};
