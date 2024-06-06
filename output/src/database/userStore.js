"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserStore = void 0;
const CertError_1 = require("../webservertypes/CertError");
const bcrypt_1 = __importDefault(require("bcrypt"));
class UserStore {
    static init(certificateDb) {
        if (certificateDb == null)
            throw new Error("Missing value for certficateDb");
        UserStore._userDb = certificateDb;
    }
    static authenticate(username, password) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne({ username: username });
        return user != null && bcrypt_1.default.compareSync(password, user.password);
    }
    static getUser(username) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        return UserStore._userDb.findOne({ username: username }) != null;
    }
}
exports.UserStore = UserStore;
UserStore._userDb = null;
//# sourceMappingURL=userStore.js.map