import { ResponseMessage, ResultType } from "./OperationResult";

/** Extends the standard Error type and adds an HTTP status code for return to the client */
export class CertError extends Error {
    /** HTTP status code - 200, 404, et al */
    public status: number;
    /**
     * Adds the status code to the constructor
     * 
     * @constructor
     * @param status HTTP status code
     * @param message Error message
     */
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }

    public getResponse(): ResponseMessage {
        return {
            success: false,
            title: "Error",
            messages: [
                {
                    message: this.message,
                    type: ResultType.Failed
                }
            ]
        };
    }
}
