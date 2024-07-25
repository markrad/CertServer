"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertTypes = void 0;
/**
 * Supported object types
 */
var CertTypes;
(function (CertTypes) {
    /** Self-signed root certificate */
    CertTypes[CertTypes["root"] = 0] = "root";
    /** Intermediate certificate signed by something else but can sign certificates itself */
    CertTypes[CertTypes["intermediate"] = 1] = "intermediate";
    /** Leaf certificate that cannot sign other certificates */
    CertTypes[CertTypes["leaf"] = 2] = "leaf";
    /** Private key */
    CertTypes[CertTypes["key"] = 3] = "key";
    /** User account */
    CertTypes[CertTypes["user"] = 4] = "user";
})(CertTypes || (exports.CertTypes = CertTypes = {}));
//# sourceMappingURL=CertTypes.js.map