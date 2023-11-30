"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionParent = void 0;
class ExtensionParent {
    toString() {
        let copy = structuredClone(this._options);
        delete copy.value;
        delete copy.name;
        return '            Name: ' + this._options.name + '\r\n                ' + JSON.stringify(copy);
    }
}
exports.ExtensionParent = ExtensionParent;
//# sourceMappingURL=ExtensionParent.js.map