import { CertError } from "../webservertypes/CertError";
import { UserRow } from "./UserRow";
import bcrypt from 'bcrypt';

export class UserStore {
    private static _userDb: Collection<UserRow> = null;

    public static init(certificateDb: Collection<UserRow>) {
        if (certificateDb == null) throw new Error("Missing value for certficateDb");

        UserStore._userDb = certificateDb;
    }

    public static authenticate(username: string, password: string): boolean {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");
        if (!password) throw new CertError(400, "Password is required");

        let user = UserStore._userDb.findOne({ username: username });

        return user != null && bcrypt.compareSync(password, user.password);
    }

    public static getUser(username: string): boolean {
        if (UserStore._userDb == null) throw new CertError(500, "UserStore not initialized");
        if (!username) throw new CertError(400, "Username is required");

        return UserStore._userDb.findOne({ username: username }) != null;
    }
}