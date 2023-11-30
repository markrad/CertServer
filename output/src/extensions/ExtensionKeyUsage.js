"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionKeyUsage = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionKeyUsage extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        this._options = options;
    }
    getObject() {
        return Object.assign({ name: ExtensionKeyUsage.extensionName }, this._options);
    }
}
exports.ExtensionKeyUsage = ExtensionKeyUsage;
ExtensionKeyUsage.extensionName = 'keyUsage';
ExtensionKeyUsage.extensionOID = '2.5.29.15';
//# sourceMappingURL=ExtensionKeyUsage.js.map