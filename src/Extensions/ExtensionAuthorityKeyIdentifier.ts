import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

type ExtensionAuthorityKeyIdentifierOptons = {
    authorityCertIssuer: boolean,
    serialNumber: string
};
type ExtensionAuthorityKeyIdentifierObject = ExtensionParentObject & {}

export class ExtensionAuthorityKeyIdentifier extends ExtensionParent {
    static readonly extensionName: string = 'authorityKeyIdentifier';
    static readonly extensionOID = '2.5.29.35';
    protected _options: any;
    constructor(options: ExtensionAuthorityKeyIdentifierOptons) {
        super();
        this._options = options;
    }

    getObject(): ExtensionAuthorityKeyIdentifierObject {
        return { ...{ name: ExtensionAuthorityKeyIdentifier.extensionName }, ...this._options }
    }
}
