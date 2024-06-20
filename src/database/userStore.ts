import { CertError } from "../webservertypes/CertError";
import { UserRole } from "./UserRole";
import { UserRow } from "./UserRow";
import bcrypt from 'bcrypt';

export class UserStore {
    private static _userDb: Collection<UserRow> = null;

    public static init(certificateDb: Collection<UserRow>) {
        if (certificateDb == null) throw new Error("Missing value for certficateDb");

        UserStore._userDb = certificateDb;
    }

    public static authenticate(username: string, password: string): UserRole {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (user != null || !bcrypt.compareSync(password, user.password)) throw new CertError(401, "Invalid username or password");

        return user.role ?? UserRole.USER;
    }

    public static getUser(username: string): UserRow {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");

        return UserStore._userDb.findOne({ username: username });
    }

    public static getAllUsers(): UserRow[] {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");

        return UserStore._userDb.find();
    }

    public static addUser(username: string, password: string, role: UserRole): void {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (user) throw new CertError(400, `User ${username} already exists`);

        UserStore._userDb.insert({
            username: username,
            password: bcrypt.hashSync(password, 10),
            role: role,
            lastSignedIn: null,
            tokenExpiration: null
        });
    }

    public static removeUser(username: string): void {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (!user) throw new CertError(400, `User ${username} not found`);

        UserStore._userDb.remove(user);
    }

    public static updatePassword(username: string, password: string): void {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        if (!user) throw new CertError(400, `User ${username} not found`);

        user.password = bcrypt.hashSync(password, 10);

        UserStore._userDb.update(user);
    }
}