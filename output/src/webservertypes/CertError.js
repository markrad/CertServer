"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertError = void 0;
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
//# sourceMappingURL=CertError.js.map