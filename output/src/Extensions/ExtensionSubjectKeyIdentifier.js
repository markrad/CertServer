"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionSubjectKeyIdentifier = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionSubjectKeyIdentifier extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        this._options = options;
    }
    getObject() {
        return Object.assign({ name: ExtensionSubjectKeyIdentifier.extensionName }, this._options);
    }
}
exports.ExtensionSubjectKeyIdentifier = ExtensionSubjectKeyIdentifier;
ExtensionSubjectKeyIdentifier.extensionName = 'subjectKeyIdentifier';
ExtensionSubjectKeyIdentifier.extensionOID = '2.5.29.14';
//# sourceMappingURL=ExtensionSubjectKeyIdentifier.js.map