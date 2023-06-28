"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionAuthorityKeyIdentifier = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionAuthorityKeyIdentifier extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        this._options = options;
    }
    getObject() {
        return Object.assign({ name: ExtensionAuthorityKeyIdentifier.extensionName }, this._options);
    }
}
exports.ExtensionAuthorityKeyIdentifier = ExtensionAuthorityKeyIdentifier;
ExtensionAuthorityKeyIdentifier.extensionName = 'authorityKeyIdentifier';
ExtensionAuthorityKeyIdentifier.extensionOID = '2.5.29.35';
//# sourceMappingURL=ExtensionAuthorityKeyIdentifier.js.map