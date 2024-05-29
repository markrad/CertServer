"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperationResult = exports.ResultType = void 0;
const OperationResultItem_1 = require("./OperationResultItem");
var ResultType;
(function (ResultType) {
    ResultType[ResultType["Success"] = 0] = "Success";
    ResultType[ResultType["Failed"] = 1] = "Failed";
})(ResultType || (exports.ResultType = ResultType = {}));
;
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
        this._messages = [];
        this._statusCode = 200;
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
     * Pushes a message to the operation result.
     *
     * @param message - The message to be pushed.
     * @param type - The type of the message.
     * @returns The updated OperationResult instance.
     */
    pushMessage(message, type) {
        this._messages.push({ type: type, message: message });
        return this;
    }
    /**
     * Sets the status code for the operation result.
     *
     * @param code - The status code to set.
     * @returns The updated OperationResult instance.
     */
    setStatusCode(code) {
        this._statusCode = code;
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
        this._messages = this._messages.concat(mergeIn._messages);
        this._statusCode = mergeIn.statusCode;
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
     * Gets the messages associated with the operation result.
     * @returns An array of ResultMessages objects.
     */
    get messages() { return this._messages; }
    get statusCode() { return this._statusCode; }
    /**
     * Gets the number of error messages in the operation result.
     * @returns The number of error messages.
     */
    get errorCount() {
        return this.messages.filter((m) => m.type === ResultType.Failed).length;
    }
    /**
     * Gets a value indicating whether the operation result has any errors.
     * @returns A boolean value indicating whether the operation result has any errors.
     */
    get hasErrors() {
        return this.messages.some((m) => m.type === ResultType.Failed);
    }
    /**
     * Gets a summary message based on the number of errors in the operation result.
     * @returns A string representing the summary message.
     */
    getMessageSummary() {
        let errorCount = this.messages.filter((m) => m.type === ResultType.Failed).length;
        return errorCount == 0
            ? "Success"
            : errorCount == 1
                ? "Error"
                : `${errorCount} Errors`;
    }
    /**
     * Retrieves the response message for the operation result.
     * @returns The response message object.
     */
    getResponse() {
        return {
            success: !this.hasErrors,
            title: this.getMessageSummary(),
            messages: this.messages
        };
    }
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