"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyEncryption = void 0;
/**
 * Enum representing the encryption options for keys.
 */
var KeyEncryption;
(function (KeyEncryption) {
    /** No encryption */
    KeyEncryption[KeyEncryption["NONE"] = 0] = "NONE";
    /** User encrypted */
    KeyEncryption[KeyEncryption["USER"] = 1] = "USER";
    /** System encrypted */
    KeyEncryption[KeyEncryption["SYSTEM"] = 2] = "SYSTEM";
})(KeyEncryption || (exports.KeyEncryption = KeyEncryption = {}));
;
//# sourceMappingURL=keyEncryption.js.map