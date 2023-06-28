import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

type ExtensionExtKeyUsageOptions = {
    serverAuth?: boolean;
    clientAuth?: boolean;
    codeSigning?: boolean;
    emailProtection?: boolean;
    timeStamping?: boolean;
    OCSPSigning?: boolean;
    ipsecIKE?: boolean;
    msCodeInd?: boolean;
    msCodeCom?: boolean;
    msCTLSign?: boolean;
    msEFS?: boolean;
};

type ExtensionExtKeyUsageObject = ExtensionParentObject & {}

export class ExtensionExtKeyUsage extends ExtensionParent {
    static readonly extensionName: string = 'extKeyUsage';
    static readonly extensionOID = '2.5.29.37';
    protected _options: ExtensionExtKeyUsageOptions;
    constructor(options: ExtensionExtKeyUsageOptions) {
        super();
        this._options = options;
    }

    getObject(): ExtensionExtKeyUsageObject {
        return { ...{ name: ExtensionExtKeyUsage.extensionName }, ...this._options }
    }
}
