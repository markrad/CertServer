"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.userAgentOS = void 0;
/**
 * Possible OS versions derived from user agent string
 */
var userAgentOS;
(function (userAgentOS) {
    userAgentOS[userAgentOS["UNKNOWN"] = 0] = "UNKNOWN";
    userAgentOS[userAgentOS["WINDOWS"] = 1] = "WINDOWS";
    userAgentOS[userAgentOS["MAC"] = 2] = "MAC";
    userAgentOS[userAgentOS["LINUX"] = 3] = "LINUX";
    userAgentOS[userAgentOS["ANDROID"] = 4] = "ANDROID";
    userAgentOS[userAgentOS["IPHONE"] = 5] = "IPHONE";
})(userAgentOS = exports.userAgentOS || (exports.userAgentOS = {}));
//# sourceMappingURL=userAgentOS.js.map