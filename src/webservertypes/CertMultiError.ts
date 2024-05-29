import { CertError } from "./CertError";
import { ResponseMessage, ResultType } from "./OperationResult";


/**
 * Represents an error that occurs when multiple certificates are involved.
 */
export class CertMultiError extends CertError {
    public certs: number[];

    /**
     * Creates a new instance of the CertMultiError class.
     * @param status The status code of the error.
     * @param message The error message.
     * @param certNumbers The numbers of the certificates involved in the error.
     */
    constructor(status: number, message: string, certNumbers: number[]) {
        super(status, message);
        this.certs = certNumbers;
    }
    
    public getResponse(): ResponseMessage {
        return {
            success: false,
            title: "Certificate Error",
            messages: [
                {
                    message: this.message,
                    type: ResultType.Failed
                }
            ],
            ids: this.certs
        };
    }

    static getCertError(err: Error): CertError | CertMultiError {
        return (err instanceof CertMultiError) 
            ? err 
            : err instanceof CertError 
            ? err
            : new CertError(500, err.message);
    }
}
