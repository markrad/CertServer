"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertError = void 0;
const OperationResult_1 = require("./OperationResult");
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
    getResponse() {
        return {
            success: false,
            title: "Error",
            messages: [
                {
                    message: this.message,
                    type: OperationResult_1.ResultType.Failed
                }
            ]
        };
    }
}
exports.CertError = CertError;
//# sourceMappingURL=CertError.js.map