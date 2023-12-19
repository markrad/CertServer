"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.exists = void 0;
const promises_1 = require("fs/promises");
/**
 * Async version of the fs exists function that is not provided by the standard node package
 *
 * @param filename The name of the file to check for existence
 * @returns True if it exists otherwise false
 */
function exists(filename) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, _reject) => __awaiter(this, void 0, void 0, function* () {
            try {
                yield (0, promises_1.access)(filename, promises_1.constants.F_OK);
                resolve(true);
            }
            catch (err) {
                resolve(false);
            }
        }));
    });
}
exports.exists = exists;
//# sourceMappingURL=exists.js.map