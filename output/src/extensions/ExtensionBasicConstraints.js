"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionBasicConstraints = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionBasicConstraints extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        this._options = options;
    }
    getObject() {
        return Object.assign({ name: ExtensionBasicConstraints.extensionName }, this._options);
    }
}
exports.ExtensionBasicConstraints = ExtensionBasicConstraints;
ExtensionBasicConstraints.extensionName = 'basicConstraints';
ExtensionBasicConstraints.extensionOID = '2.5.29.19';
//# sourceMappingURL=ExtensionBasicConstraints.js.map