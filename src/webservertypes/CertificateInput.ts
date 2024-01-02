import { ExtensionSubjectAltNameOptions } from "../extensions/ExtensionSubjectAltName"
import { CertificateSubject } from "./CertificateSubject"

export type CertificateInput = {
    validFrom: Date,
    validTo: Date,
    subject: CertificateSubject,
    san: ExtensionSubjectAltNameOptions,
}