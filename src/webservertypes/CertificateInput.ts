import { ExtensionSubjectAltNameOptions } from "../extensions/ExtensionSubjectAltName"
import { CertificateSubject } from "./CertificateSubject"

export type CertificateInput = {
    validFrom: Date,
    validTo: Date,
    signer: string,
    password: string,
    subject: CertificateSubject,
    san: ExtensionSubjectAltNameOptions,
}