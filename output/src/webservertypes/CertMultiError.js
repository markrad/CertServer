"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertMultiError = void 0;
const CertError_1 = require("./CertError");
class CertMultiError extends CertError_1.CertError {
    constructor(status, message, certNumbers) {
        super(status, message);
        this.certs = certNumbers;
    }
}
exports.CertMultiError = CertMultiError;
//# sourceMappingURL=CertMultiError.js.map