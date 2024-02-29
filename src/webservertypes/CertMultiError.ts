import { CertError } from "./CertError";


export class CertMultiError extends CertError {
    public certs: number[];
    constructor(status: number, message: string, certNumbers: number[]) {
        super(status, message);
        this.certs = certNumbers;
    }
}
