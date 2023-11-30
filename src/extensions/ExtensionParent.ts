export type ExtensionParentObject = {
    name?: string;
    critical?: boolean;
};

export abstract class ExtensionParent {
    protected abstract _options: any;
    abstract getObject(): any;
    toString(): string {
        let copy = structuredClone(this._options);
        delete copy.value;
        delete copy.name;
        return '            Name: ' + this._options.name + '\r\n                ' + JSON.stringify(copy);
    }
}
