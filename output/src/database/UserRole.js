"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRole = void 0;
/**
 * Represents the role of a user.
 */
var UserRole;
(function (UserRole) {
    /**
     * The unknown role is used when the user identity or password is not invalid.
     */
    UserRole[UserRole["UNKNOWN"] = -1] = "UNKNOWN";
    /**
     * The admin role has the highest privileges including the ability to create and delete users.
     */
    UserRole[UserRole["ADMIN"] = 0] = "ADMIN";
    /**
     * The user role is the default role.
     */
    UserRole[UserRole["USER"] = 1] = "USER";
})(UserRole || (exports.UserRole = UserRole = {}));
//# sourceMappingURL=UserRole.js.map