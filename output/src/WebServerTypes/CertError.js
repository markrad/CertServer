"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertError = void 0;
class CertError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}
exports.CertError = CertError;
//# sourceMappingURL=CertError.js.map