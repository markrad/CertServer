"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertTypes = void 0;
/**
 * Supported X.509 object types
 */
var CertTypes;
(function (CertTypes) {
    // TODO - deprecate this. Will require massive database update to achieve.
    CertTypes[CertTypes["cert"] = 0] = "cert";
    /** Self-signed root certificate */
    CertTypes[CertTypes["root"] = 1] = "root";
    /** Intermediate certificate signed by something else but can sign certificates itself */
    CertTypes[CertTypes["intermediate"] = 2] = "intermediate";
    /** Leaf certificate that cannot sign other certificates */
    CertTypes[CertTypes["leaf"] = 3] = "leaf";
    /** Private key */
    CertTypes[CertTypes["key"] = 4] = "key";
})(CertTypes = exports.CertTypes || (exports.CertTypes = {}));
//# sourceMappingURL=CertTypes.js.map