import { CertError } from "../webservertypes/CertError";
import { CertTypes } from "../webservertypes/CertTypes";
import { OperationResult, ResultType } from "../webservertypes/OperationResult";
import { OperationResultItem } from "../webservertypes/OperationResultItem";
import { UserRole } from "./UserRole";
import { UserRow } from "./UserRow";
import bcrypt from 'bcrypt';

export class UserStore {
    private static _userDb: Collection<UserRow> = null;

    /**
     * Initializes the UserStore with the provided certificate database.
     * @param certificateDb - The certificate database collection.
     * @throws {Error} If the certificateDb parameter is null or undefined.
     */
    public static init(certificateDb: Collection<UserRow>) {
        if (certificateDb == null) throw new Error("Missing value for certficateDb");

        UserStore._userDb = certificateDb;
    }

    /**
     * Authenticates a user with the given username and password.
     * @param {string} username - The username of the user.
     * @param {string} password - The password of the user.
     * @returns {UserRole} The role of the authenticated user.
     * @throws {CertError} If the UserStore is not initialized, or if the username or password is missing or invalid.
     */
    public static authenticate(username: string, password: string): UserRole {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (user == null || !bcrypt.compareSync(password, user.password)) throw new CertError(401, "Invalid username or password");

        return user.role ?? UserRole.USER;
    }

    /**
     * Retrieves a user from the user store based on the provided username or ID.
     * @param user - The username or ID of the user to retrieve.
     * @returns The user object matching the provided username or ID.
     * @throws {CertError} with status code 500 if the UserStore is not initialized.
     * @throws {CertError} with status code 400 if the username is not provided.
     */
    public static getUser(user: string | number): UserRow & LokiObj {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!user) throw new CertError(400, "Username is required");

        return typeof user == 'string'
            ? UserStore._userDb.findOne({ username: user })
            : UserStore._userDb.findOne({ $loki: user });
    }

    /**
     * Retrieves all users from the user store.
     * @returns An array of user objects.
     * @throws {CertError} If the user store is not initialized.
     */
    public static getAllUsers(): (UserRow & LokiObj)[] {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");

        return UserStore._userDb.find();
    }

    /**
     * Retrieves an array of user rows based on the specified role.
     * @param role - The role of the users to retrieve.
     * @returns An array of user rows matching the specified role.
     * @throws {CertError} if the UserStore is not initialized.
     */
    public static getUsersByRole(role: UserRole): UserRow[] {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");

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
    public static addUser(username: string, password: string, role: UserRole): OperationResult {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (user) throw new CertError(400, `User ${username} already exists`);

        let newRow: UserRow & LokiObj = UserStore._userDb.insert({
            username: username,
            password: bcrypt.hashSync(password, 10),
            role: role,
            lastSignedIn: null,
            tokenExpiration: null
        }) as UserRow & LokiObj;

        return new OperationResult(newRow.username)
            .pushAdded(OperationResultItem.makeResult({type: CertTypes.user, id: newRow.$loki}))
            .pushMessage(`User ${newRow.username} added`, ResultType.Success);
    }

    /**
     * Removes a user from the user store.
     * @param username - The username or ID of the user to remove.
     * @returns An `OperationResult` indicating the result of the operation.
     * @throws {CertError} if the user store is not initialized, username is not provided, or the user is not found.
     */
    public static removeUser(username: string | number): OperationResult {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");

        let user = UserStore._userDb.findOne(typeof username == 'string'? { username: username } : { $loki: username });

        if (!user) throw new CertError(404, `User ${username} not found`);

        let res: OperationResult = new OperationResult(user.username);
        res.pushDeleted(OperationResultItem.makeResult({type: CertTypes.user, id: user.$loki})).pushMessage(`User ${user.username} removed`, ResultType.Success);
        UserStore._userDb.remove(user);

        return res;
    }

    /**
     * Updates the role of a user in the user store.
     * @param {string} username - The username of the user.
     * @param {UserRole} role - The new role for the user.
     * @throws {CertError} If the user store is not initialized, username is empty, or the user is not found.
     */
    public static updateRole(username: string, role: UserRole): void {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (!user) throw new CertError(404, `User ${username} not found`);

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
    public static updatePassword(username: string | number, password: string): OperationResult {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne(typeof username == 'string'? { username: username } : { $loki: username });

        if (!user) throw new CertError(404, `User ${username} not found`);

        user.password = bcrypt.hashSync(password, 10);
        let res: OperationResult = new OperationResult(user.username);
        UserStore._userDb.update(user);
        res.pushUpdated(OperationResultItem.makeResult({type: CertTypes.user, id: user.$loki})).pushMessage(`Password for user ${user.username} updated`, ResultType.Success);
        return res;
    }
}