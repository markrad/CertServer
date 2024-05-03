"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperationResult = void 0;
// import { CertificateUtil } from '../database/certificateUtil';
// import { CertTypes } from './CertTypes';
const OperationResultItem_1 = require("./OperationResultItem");
class OperationResult {
    constructor(name) {
        this._name = "";
        this._added = [];
        this._updated = [];
        this._deleted = [];
        if (name)
            this._name = name;
    }
    static createFromJSON(json) {
        let o = JSON.parse(json);
        let ret = new OperationResult(o.name);
        for (let a in o.added) {
            ret.pushAdded(new OperationResultItem_1.OperationResultItem(o.added[a].type, o.added[a].id));
        }
        for (let a in o.updated) {
            ret.pushAdded(new OperationResultItem_1.OperationResultItem(o.updated[a].type, o.updated[a].id));
        }
        for (let a in o.deleted) {
            ret.pushAdded(new OperationResultItem_1.OperationResultItem(o.deleted[a].type, o.deleted[a].id));
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
    pushAdded(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.added.push(r);
        }
        return this;
    }
    pushUpdated(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.updated.push(r);
        }
        return this;
    }
    pushDeleted(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.deleted.push(r);
        }
        return this;
    }
    merge(mergeIn) {
        // TODO: Do we really need to dedup these?
        let i;
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
    normalize() {
        for (let i of this.added) {
            this._updated = this.updated.filter((u) => !u.isEqual(i));
        }
        return this;
    }
    get name() { return this._name; }
    set name(newValue) { this._name = newValue; }
    get added() { return this._added; }
    get updated() { return this._updated; }
    get deleted() { return this._deleted; }
    toJSON() {
        return {
            name: this.name,
            added: this.added,
            updated: this.updated,
            deleted: this.deleted
        };
    }
}
exports.OperationResult = OperationResult;
//# sourceMappingURL=OperationResult.js.map