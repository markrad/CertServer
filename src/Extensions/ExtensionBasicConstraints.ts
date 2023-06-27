import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

type ExtensionBasicConstraintsOptions = {
    cA: boolean,
    pathlenConstraint?: number
}

type ExtensionBasicConstraintsObject = ExtensionParentObject & ExtensionBasicConstraintsOptions & {}

export class ExtensionBasicConstraints extends ExtensionParent {
    static readonly extensionName: string = 'basicConstraints';
    static readonly extensionOID = '2.5.29.19';
    protected _options: ExtensionBasicConstraintsOptions;
    constructor(options: ExtensionBasicConstraintsOptions) {
        super();
        this._options = options;
    }

    getObject(): ExtensionBasicConstraintsObject {
        return { ...{ name: ExtensionBasicConstraints.extensionName }, ...this._options }
    }
}
