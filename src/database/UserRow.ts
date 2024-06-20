import { UserRole } from "./UserRole";

/**
 * Represents a user row in the database.
 */
export interface UserRow {
    username: string;
    password: string;
    role: UserRole
    lastSignedIn: Date;
    tokenExpiration: Date;
};
