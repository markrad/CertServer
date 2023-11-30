"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionExtKeyUsage = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionExtKeyUsage extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        this._options = options;
    }
    getObject() {
        return Object.assign({ name: ExtensionExtKeyUsage.extensionName }, this._options);
    }
}
exports.ExtensionExtKeyUsage = ExtensionExtKeyUsage;
ExtensionExtKeyUsage.extensionName = 'extKeyUsage';
ExtensionExtKeyUsage.extensionOID = '2.5.29.37';
//# sourceMappingURL=ExtensionExtKeyUsage.js.map