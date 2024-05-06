"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperationResultItem = void 0;
/**
 * Represents an operation result item.
 */
class OperationResultItem {
    /**
     * Creates an instance of OperationResultItem based on the provided ResultItem.
     * @param value - The ResultItem object to create the OperationResultItem from.
     * @returns A new instance of OperationResultItem.
     */
    static makeResult(value) {
        return new OperationResultItem(value.type, value.id);
    }
    /**
     * Creates an instance of OperationResultItem.
     * @constructor
     * @param certType - The type of the operation result item.
     * @param id - The id of the affected item.
     */
    constructor(certType, id) {
        this._certType = certType;
        this._id = id;
    }
    /**
     * Gets the type of the operation result item.
     * @returns The type of the operation result item.
     */
    get type() { return this._certType; }
    /**
     * Get the id of the affected item.
     * @returns The id of the affected item.
     */
    get id() { return this._id; }
    /**
     * Checks if the current `OperationResultItem` instance is equal to the provided `inputItem` instance.
     * Two instances are considered equal if their `id` and `type` properties are equal.
     *
     * @param inputItem - The `OperationResultItem` instance to compare with.
     * @returns `true` if the instances are equal, `false` otherwise.
     */
    isEqual(inputItem) {
        return (this.id == inputItem.id && this.type == inputItem.type);
    }
    /**
     * This will be called by JSON.stringify. If removes the leading underscores from the private variable names.
     * @returns The object with sensible names.
     */
    toJSON() {
        return {
            type: this.type,
            id: this.id,
        };
    }
}
exports.OperationResultItem = OperationResultItem;
//# sourceMappingURL=OperationResultItem.js.map