"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertMultiError = void 0;
const CertError_1 = require("./CertError");
const OperationResult_1 = require("./OperationResult");
/**
 * Represents an error that occurs when multiple certificates are involved.
 */
class CertMultiError extends CertError_1.CertError {
    /**
     * Creates a new instance of the CertMultiError class.
     * @param status The status code of the error.
     * @param message The error message.
     * @param certNumbers The numbers of the certificates involved in the error.
     */
    constructor(status, message, certNumbers) {
        super(status, message);
        this.certs = certNumbers;
    }
    getResponse() {
        return {
            success: false,
            title: "Certificate Error",
            messages: [
                {
                    message: this.message,
                    type: OperationResult_1.ResultType.Failed
                }
            ],
            ids: this.certs
        };
    }
    static getCertError(err) {
        return (err instanceof CertMultiError)
            ? err
            : err instanceof CertError_1.CertError
                ? err
                : new CertError_1.CertError(500, err.message);
    }
}
exports.CertMultiError = CertMultiError;
//# sourceMappingURL=CertMultiError.js.map