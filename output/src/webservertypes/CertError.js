"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertMultiError = exports.CertError = void 0;
/** Extends the standard Error type and adds an HTTP status code for return to the client */
class CertError extends Error {
    /**
     * Adds the status code to the constructor
     *
     * @constructor
     * @param status HTTP status code
     * @param message Error message
     */
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}
exports.CertError = CertError;
class CertMultiError extends CertError {
    constructor(status, message, certNumbers) {
        super(status, message);
        this.certs = certNumbers;
    }
}
exports.CertMultiError = CertMultiError;
//# sourceMappingURL=CertError.js.map