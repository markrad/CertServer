// import { CertificateUtil } from '../database/certificateUtil';
// import { CertTypes } from './CertTypes';
import { OperationResultItem } from './OperationResultItem';

export class OperationResult {
    private _name: string = "";
    private _added: OperationResultItem[] = [];
    private _updated: OperationResultItem[] = [];
    private _deleted: OperationResultItem[] = [];

    constructor(name?: string) {
        if (name) this._name = name;
    }

    public static createFromJSON(json: string):OperationResult {
        let o: any = JSON.parse(json);
        let ret = new OperationResult(o.name);

        for (let a in o.added) {
            ret.pushAdded(new OperationResultItem(o.added[a].type, o.added[a].id));
        }

        for (let a in o.updated) {
            ret.pushAdded(new OperationResultItem(o.updated[a].type, o.updated[a].id));
        }

        for (let a in o.deleted) {
            ret.pushAdded(new OperationResultItem(o.deleted[a].type, o.deleted[a].id));
        }

        return ret;
    }

    // private _getResultItem(...args: [OperationResultItem2] | [CertTypes, number]): OperationResultItem2 {
    //     if (args.length == 1) {
    //         if (!(args[0] instanceof OperationResultItem2)) {
    //             throw new Error('Invalid type passed to push function');
    //         }
    //         return args[0];
    //     }
    //     else {
    //         return new OperationResultItem2(args[0], args[1]);
    //     }

    // }

    public pushAdded(result: OperationResultItem | OperationResultItem[]): OperationResult {
        if (!Array.isArray(result)) {
            result = [ result ];
        }

        for (let r of result) {
            this.added.push(r);
        }
        return this;
    }

    public pushUpdated(result: OperationResultItem | OperationResultItem[]): OperationResult {
        if (!Array.isArray(result)) {
            result = [ result] ;
        }

        for (let r of result) {
            this.updated.push(r);
        }
        return this;
    }

    public pushDeleted(result: OperationResultItem | OperationResultItem[]): OperationResult {
        if (!Array.isArray(result)) {
            result = [result];
        }

        for (let r of result) {
            this.deleted.push(r);
        }
        return this;
    }

    public merge(mergeIn: OperationResult): void {
        // TODO: Do we really need to dedup these?
        let i: string;
        for (i in mergeIn.added) {
            if (!this.added.some((value) => value.isEqual(mergeIn.added[i]))) {
                this.added.push(mergeIn.added[i]);
            }
        }

        for (i in mergeIn.updated) {
            if (!this.updated.some((value) => value.isEqual(mergeIn.updated[i]))) {
                this.updated.push(mergeIn.updated[i]);
            }
        }

        for (i in mergeIn.deleted) {
            if (!this.deleted.some((value) => value.isEqual(mergeIn.deleted[i]))) {
                this.deleted.push(mergeIn.deleted[i]);
            }
        }
    }

    public normalize(): OperationResult {
        for (let i of this.added) {
            this._updated = this.updated.filter((u) => !u.isEqual(i));
        }
        return this;
    }

    public get name(): string { return this._name; }
    public set name(newValue: string) { this._name = newValue; }
    public get added(): OperationResultItem[] { return this._added; }
    public get updated(): OperationResultItem[] { return this._updated; }
    public get deleted(): OperationResultItem[] { return this._deleted; }

    public toJSON(): Object {
        return {
            name: this.name,
            added: this.added,
            updated: this.updated,
            deleted: this.deleted
        }
    }
}
