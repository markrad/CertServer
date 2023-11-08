import { OperationResultItem } from './OperationResultItem';

/**
 * Used to return database entries that have been added, deleted, or updated.
 *
 * @member name: The common name of the certificate or key - will be deprecated
 * @member types Deprecated
 * @member added Array of certificates or keys added
 * @member updated Array of certificates or keys updated
 * @member deleted Array of certificates or keys deleted
 */
export type OperationResult = {
    name: string;
    added: OperationResultItem[];
    updated: OperationResultItem[];
    deleted: OperationResultItem[];
};
