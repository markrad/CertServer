"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserStore = void 0;
const CertError_1 = require("../webservertypes/CertError");
const UserRole_1 = require("./UserRole");
const bcrypt_1 = __importDefault(require("bcrypt"));
class UserStore {
    static init(certificateDb) {
        if (certificateDb == null)
            throw new Error("Missing value for certficateDb");
        UserStore._userDb = certificateDb;
    }
    static authenticate(username, password) {
        var _a;
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (user != null || !bcrypt_1.default.compareSync(password, user.password))
            throw new CertError_1.CertError(401, "Invalid username or password");
        return (_a = user.role) !== null && _a !== void 0 ? _a : UserRole_1.UserRole.USER;
    }
    static getUser(username) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        return UserStore._userDb.findOne({ username: username });
    }
    static getAllUsers() {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        return UserStore._userDb.find();
    }
    static addUser(username, password, role) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (user)
            throw new CertError_1.CertError(400, `User ${username} already exists`);
        UserStore._userDb.insert({
            username: username,
            password: bcrypt_1.default.hashSync(password, 10),
            role: role,
            lastSignedIn: null,
            tokenExpiration: null
        });
    }
    static removeUser(username) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (!user)
            throw new CertError_1.CertError(400, `User ${username} not found`);
        UserStore._userDb.remove(user);
    }
    static updatePassword(username, password) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (!user)
            throw new CertError_1.CertError(400, `User ${username} not found`);
        user.password = bcrypt_1.default.hashSync(password, 10);
        UserStore._userDb.update(user);
    }
}
exports.UserStore = UserStore;
UserStore._userDb = null;
//# sourceMappingURL=userStore.js.map