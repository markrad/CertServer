import { ExtensionParent, ExtensionParentObject } from "./ExtensionParent";

type ExtensionSubjectKeyIdentifierOptions = {};
type ExtensionSubjectKeyIdentifierObject = ExtensionParentObject & { subjectKeyIdentifier?: string }

export class ExtensionSubjectKeyIdentifier extends ExtensionParent {
    static readonly extensionName: string = 'subjectKeyIdentifier';
    static readonly extensionOID = '2.5.29.14';
    protected _options: ExtensionSubjectKeyIdentifierOptions;
    constructor(options: ExtensionSubjectKeyIdentifierOptions) {
        super();
        this._options = options;
    }

    getObject(): ExtensionSubjectKeyIdentifierObject {
        return { ...{ name: ExtensionSubjectKeyIdentifier.extensionName } }
    }
}
