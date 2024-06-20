/**
 * Represents the role of a user.
 */
export enum UserRole {
    /**
     * The unknown role is used when the user identity or password is not invalid.
     */
    UNKNOWN = -1,
    /**
     * The admin role has the highest privileges including the ability to create and delete users.
     */
    ADMIN = 0,
    /**
     * The user role is the default role.
     */ 
    USER = 1
}
