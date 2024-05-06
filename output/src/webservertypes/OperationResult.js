"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperationResult = void 0;
const OperationResultItem_1 = require("./OperationResultItem");
/**
 * Represents the result of an operation.
 */
class OperationResult {
    /**
     * Creates an OperationResult.
     * @constructor
     * @param {string} [name] - The name of the OperationResult.
     */
    constructor(name) {
        this._name = "";
        this._added = [];
        this._updated = [];
        this._deleted = [];
        if (name)
            this._name = name;
    }
    /**
     * Creates an OperationResult object from a JSON string.
     * @param json - The JSON string representing the OperationResult object.
     * @returns The OperationResult object created from the JSON string.
     */
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
    /**
     * Adds one or more items to the `added` array of the `OperationResult` object.
     *
     * @param result - The item or items to be added.
     * @returns The updated `OperationResult` object.
     */
    pushAdded(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.added.push(r);
        }
        return this;
    }
    /**
     * Pushes the updated operation result item(s) to the `updated` array.
     *
     * @param result - The operation result item(s) to be pushed.
     * @returns The updated `OperationResult` instance.
     */
    pushUpdated(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.updated.push(r);
        }
        return this;
    }
    /**
     * Pushes the specified `OperationResultItem` or an array of `OperationResultItem` objects to the `deleted` array.
     *
     * @param result - The `OperationResultItem` or an array of `OperationResultItem` objects to push to the `deleted` array.
     * @returns The updated `OperationResult` instance.
     */
    pushDeleted(result) {
        if (!Array.isArray(result)) {
            result = [result];
        }
        for (let r of result) {
            this.deleted.push(r);
        }
        return this;
    }
    /**
     * Merges the specified `OperationResult` into the current instance.
     * @param mergeIn The `OperationResult` to merge.
     */
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
    /**
     * Normalizes the OperationResult by removing any duplicates from the updated array.
     * Duplicates are determined by the `isEqual` method of the added items.
     *
     * @returns The normalized OperationResult.
     */
    normalize() {
        for (let i of this.added) {
            this._updated = this.updated.filter((u) => !u.isEqual(i));
        }
        return this;
    }
    /**
     * Gets the name of the operation result.
     * @returns The name of the operation result.
     */
    get name() { return this._name; }
    /**
     * Sets the name of the operation result.
     */
    set name(newValue) { this._name = newValue; }
    /**
     * Gets the array of OperationResultItem objects that were added.
     * @returns An array of OperationResultItem objects representing the added items.
     */
    get added() { return this._added; }
    /**
     * Gets the array of OperationResultItem objects that were updated.
     * @returns An array of OperationResultItem objects representing the updated items.
     */
    get updated() { return this._updated; }
    /**
     * Gets the array of OperationResultItem objects that were deleted.
     * @returns An array of OperationResultItem objects representing the added items.
     */
    get deleted() { return this._deleted; }
    /**
     * This will be called by JSON.stringify. If removes the leading underscores from the private variable names.
     * @returns The object with sensible names.
     */
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