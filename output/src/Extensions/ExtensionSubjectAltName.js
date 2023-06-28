"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionSubjectAltName = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionSubjectAltName extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        var _a, _b;
        super();
        if (options.name) {
            this._options = options;
        }
        else {
            this._options = {
                name: ExtensionSubjectAltName.extensionName,
                altNames: ((_a = options.domains) !== null && _a !== void 0 ? _a : []).map(domain => { return { type: 2, value: domain }; }).concat(((_b = options.IPs) !== null && _b !== void 0 ? _b : []).map(IP => { return { type: 7, value: IP }; }))
            };
        }
    }
    getObject() {
        return this._options;
    }
    toString() {
        let retVal;
        let alts = this._options.altNames.map((entry) => {
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
exports.ExtensionSubjectAltName = ExtensionSubjectAltName;
ExtensionSubjectAltName.extensionName = 'subjectAltName';
ExtensionSubjectAltName.extensionOID = '2.5.29.17';
//# sourceMappingURL=ExtensionSubjectAltName.js.map