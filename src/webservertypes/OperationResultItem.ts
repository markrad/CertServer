import { CertTypes } from './CertTypes';

/**
 * Represents a single modification to the database
 */
export type ResultItem = {
    /** The type entry modified either a key or a root, intermediate, or leaf certificate */
    type: CertTypes;
    /** The $loki id of the row in the database */
    id: number;
};

export class OperationResultItem {
    private _certType: CertTypes;
    private _id: number;

    public static makeResult(value: ResultItem): OperationResultItem {
        return new OperationResultItem(value.type, value.id);
    } 

    constructor(certType: CertTypes, id: number) {
        this._certType = certType;
        this._id = id;
    }

    public get type() { return this._certType; }
    public get id() { return this._id }
    public isEqual(comp: OperationResultItem): boolean {
        return (this.id == comp.id && this.type == comp.type)
    }

    public toJSON(): Object {
        return {
            type: this.type,
            id: this.id,
        }
    }
}