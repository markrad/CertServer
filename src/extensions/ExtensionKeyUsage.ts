import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

type ExtensionKeyUsageOptions = {       // Checked
    digitalSignature?: boolean;
    nonRepudiation?: boolean;
    keyEncipherment?: boolean;
    dataEncipherment?: boolean;
    keyAgreement?: boolean;
    keyCertSign?: boolean;
    cRLSign?: boolean;
    encipherOnly?: boolean;
    decipherOnly?: boolean;
}
type ExtensionKeyUsageObject = ExtensionParentObject & ExtensionKeyUsageOptions & {}

export class ExtensionKeyUsage extends ExtensionParent {
    static readonly extensionName: string = 'keyUsage';
    static readonly extensionOID = '2.5.29.15';
    protected _options: ExtensionKeyUsageOptions;
    constructor(options: ExtensionKeyUsageOptions) {
        super();
        this._options = options;
    }

    getObject(): ExtensionKeyUsageObject {
        return { ...{ name: ExtensionKeyUsage.extensionName }, ...this._options }
    }
}