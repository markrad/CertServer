import { CertTypes } from './CertTypes';

/**
 * Represents a single modification to the database in the operation result.
 */
export type ResultItem = {
    /** The type entry modified either a key or a root, intermediate, or leaf certificate */
    type: CertTypes;
    /** The $loki id of the row in the database */
    id: number;
};

/**
 * Represents an operation result item.
 */
export class OperationResultItem {
    private _certType: CertTypes;
    private _id: number;

    /**
     * Creates an instance of OperationResultItem based on the provided ResultItem.
     * @param value - The ResultItem object to create the OperationResultItem from.
     * @returns A new instance of OperationResultItem.
     */
    public static makeResult(value: ResultItem): OperationResultItem {
        return new OperationResultItem(value.type, value.id);
    } 

    /**
     * Creates an instance of OperationResultItem.
     * @constructor
     * @param certType - The type of the operation result item.
     * @param id - The id of the affected item.
     */
    constructor(certType: CertTypes, id: number) {
        this._certType = certType;
        this._id = id;
    }

    /**
     * Gets the type of the operation result item.
     * @returns The type of the operation result item.
     */
    public get type() { return this._certType; }

    /**
     * Get the id of the affected item.
     * @returns The id of the affected item.
     */
    public get id() { return this._id }

    /**
     * Checks if the current `OperationResultItem` instance is equal to the provided `inputItem` instance.
     * Two instances are considered equal if their `id` and `type` properties are equal.
     * 
     * @param inputItem - The `OperationResultItem` instance to compare with.
     * @returns `true` if the instances are equal, `false` otherwise.
     */
    public isEqual(inputItem: OperationResultItem): boolean {
        return (this.id == inputItem.id && this.type == inputItem.type)
    }

    /**
     * This will be called by JSON.stringify. If removes the leading underscores from the private variable names.
     * @returns The object with sensible names.
     */
    public toJSON(): Object {
        return {
            type: this.type,
            id: this.id,
        }
    }
}