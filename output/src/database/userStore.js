"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserStore = void 0;
const CertError_1 = require("../webservertypes/CertError");
const CertTypes_1 = require("../webservertypes/CertTypes");
const OperationResult_1 = require("../webservertypes/OperationResult");
const OperationResultItem_1 = require("../webservertypes/OperationResultItem");
const UserRole_1 = require("./UserRole");
const bcrypt_1 = __importDefault(require("bcrypt"));
class UserStore {
    /**
     * Initializes the UserStore with the provided certificate database.
     * @param certificateDb - The certificate database collection.
     * @throws {Error} If the certificateDb parameter is null or undefined.
     */
    static init(certificateDb) {
        if (certificateDb == null)
            throw new Error("Missing value for certficateDb");
        UserStore._userDb = certificateDb;
    }
    /**
     * Authenticates a user with the given username and password.
     * @param {string} username - The username of the user.
     * @param {string} password - The password of the user.
     * @returns {UserRole} The role of the authenticated user.
     * @throws {CertError} If the UserStore is not initialized, or if the username or password is missing or invalid.
     */
    static authenticate(username, password) {
        var _a;
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (user == null || !bcrypt_1.default.compareSync(password, user.password))
            throw new CertError_1.CertError(401, "Invalid username or password");
        return (_a = user.role) !== null && _a !== void 0 ? _a : UserRole_1.UserRole.USER;
    }
    /**
     * Retrieves a user from the user store based on the provided username or ID.
     * @param user - The username or ID of the user to retrieve.
     * @returns The user object matching the provided username or ID.
     * @throws {CertError} with status code 500 if the UserStore is not initialized.
     * @throws {CertError} with status code 400 if the username is not provided.
     */
    static getUser(user) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!user)
            throw new CertError_1.CertError(400, "Username is required");
        return typeof user == 'string'
            ? UserStore._userDb.findOne({ username: user })
            : UserStore._userDb.findOne({ $loki: user });
    }
    /**
     * Retrieves all users from the user store.
     * @returns An array of user objects.
     * @throws {CertError} If the user store is not initialized.
     */
    static getAllUsers() {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        return UserStore._userDb.find();
    }
    /**
     * Retrieves an array of user rows based on the specified role.
     * @param role - The role of the users to retrieve.
     * @returns An array of user rows matching the specified role.
     * @throws {CertError} if the UserStore is not initialized.
     */
    static getUsersByRole(role) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        return UserStore._userDb.find({ role: role });
    }
    /**
     * Adds a new user to the user store.
     *
     * @param username - The username of the user.
     * @param password - The password of the user.
     * @param role - The role of the user.
     * @returns An `OperationResult` object indicating the result of the operation.
     * @throws {CertError} if the user store is not initialized, or if the username or password is missing, or if the user already exists.
     */
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
        let newRow = UserStore._userDb.insert({
            username: username,
            password: bcrypt_1.default.hashSync(password, 10),
            role: role,
            lastSignedIn: null,
            tokenExpiration: null
        });
        return new OperationResult_1.OperationResult(newRow.username)
            .pushAdded(OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.user, id: newRow.$loki }))
            .pushMessage(`User ${newRow.username} added`, OperationResult_1.ResultType.Success);
    }
    /**
     * Removes a user from the user store.
     * @param username - The username or ID of the user to remove.
     * @returns An `OperationResult` indicating the result of the operation.
     * @throws {CertError} if the user store is not initialized, username is not provided, or the user is not found.
     */
    static removeUser(username) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        let user = UserStore._userDb.findOne(typeof username == 'string' ? { username: username } : { $loki: username });
        if (!user)
            throw new CertError_1.CertError(404, `User ${username} not found`);
        let res = new OperationResult_1.OperationResult(user.username);
        res.pushDeleted(OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.user, id: user.$loki })).pushMessage(`User ${user.username} removed`, OperationResult_1.ResultType.Success);
        UserStore._userDb.remove(user);
        return res;
    }
    /**
     * Updates the role of a user in the user store.
     * @param {string} username - The username of the user.
     * @param {UserRole} role - The new role for the user.
     * @throws {CertError} If the user store is not initialized, username is empty, or the user is not found.
     */
    static updateRole(username, role) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        let user = UserStore._userDb.findOne({ username: username });
        if (!user)
            throw new CertError_1.CertError(404, `User ${username} not found`);
        user.role = role;
        UserStore._userDb.update(user);
    }
    /**
     * Updates the password for a user.
     * @param username - The username or ID of the user.
     * @param password - The new password for the user.
     * @returns An `OperationResult` indicating the success or failure of the password update.
     * @throws {CertError} if the UserStore is not initialized, username is missing, password is missing, or the user is not found.
     */
    static updatePassword(username, password) {
        if (UserStore._userDb == null)
            throw new CertError_1.CertError(500, "UserStore not initialized");
        if (!username)
            throw new CertError_1.CertError(400, "Username is required");
        if (!password)
            throw new CertError_1.CertError(400, "Password is required");
        let user = UserStore._userDb.findOne(typeof username == 'string' ? { username: username } : { $loki: username });
        if (!user)
            throw new CertError_1.CertError(404, `User ${username} not found`);
        user.password = bcrypt_1.default.hashSync(password, 10);
        let res = new OperationResult_1.OperationResult(user.username);
        UserStore._userDb.update(user);
        res.pushUpdated(OperationResultItem_1.OperationResultItem.makeResult({ type: CertTypes_1.CertTypes.user, id: user.$loki })).pushMessage(`Password for user ${user.username} updated`, OperationResult_1.ResultType.Success);
        return res;
    }
}
exports.UserStore = UserStore;
UserStore._userDb = null;
//# sourceMappingURL=userStore.js.map