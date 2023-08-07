"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtensionSubjectAltName = void 0;
const ExtensionParent_1 = require("./ExtensionParent");
class ExtensionSubjectAltName extends ExtensionParent_1.ExtensionParent {
    constructor(options) {
        super();
        if (false /*options.name*/) {
            this._options = options;
        }
        else {
            this._options = {
                name: ExtensionSubjectAltName.extensionName,
                altNames: [
                    ...options.domains != undefined
                        ? options.domains.map((domain) => ({ type: 2, value: domain }))
                        : [],
                    ...options.IPs != undefined
                        ? options.IPs.map((ip) => ({ type: 7, ip: ip }))
                        : []
                ]
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