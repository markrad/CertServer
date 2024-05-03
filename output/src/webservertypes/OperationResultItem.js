"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OperationResultItem = void 0;
class OperationResultItem {
    static makeResult(value) {
        return new OperationResultItem(value.type, value.id);
    }
    constructor(certType, id) {
        this._certType = certType;
        this._id = id;
    }
    get type() { return this._certType; }
    get id() { return this._id; }
    isEqual(comp) {
        return (this.id == comp.id && this.type == comp.type);
    }
    toJSON() {
        return {
            type: this.type,
            id: this.id,
        };
    }
}
exports.OperationResultItem = OperationResultItem;
//# sourceMappingURL=OperationResultItem.js.map