import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

export type ExtensionSubjectAltNameOptions = {
    domains?: string[];
    IPs?: string[];
};

type SubjectAltName = {
    type?: number,
    value?: string,
    ip?: string,
}

type ExtensionSubjectAltNameObject = ExtensionParentObject & { altNames: SubjectAltName[] }

export class ExtensionSubjectAltName extends ExtensionParent {
    static readonly extensionName: string = 'subjectAltName';
    static readonly extensionOID = '2.5.29.17';
    protected _options: ExtensionSubjectAltNameObject;
    constructor(options: ExtensionSubjectAltNameOptions) {
        super();
        if (false /*options.name*/) {
            this._options = options as ExtensionSubjectAltNameObject;
        }
        else {
            this._options = {
                name: ExtensionSubjectAltName.extensionName,
                altNames: [
                    ...options.domains != undefined
                    ? options.domains.map((domain) => ({ type: 2, value: domain }))
                    : [],
                    ...options.IPs != undefined
                    ? options.IPs.map((ip) => ({ type: 7, ip: ip}))
                    : []
                ]
            }
        } 
    }
 
    getObject(): ExtensionSubjectAltNameObject {
        return this._options;
    }

    toString(): string {
        let retVal: string;
        let alts: string = this._options.altNames.map((entry) => {
            return entry.type == 2
                ? `DNS:${entry.value}`
                : entry.type == 7
                ? `IP:${entry.value}`
                : `${entry.type}?:${entry.value}`;
        }).join(', ');
        retVal = '            Name: ' + this._options.name + '\r\n';
        retVal += '                ' + alts;
        return retVal;
    }
}
