"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const webserver_1 = require("./webserver");
// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// TODO: Add config file or parameters
const ROOT_DIRECTORY = path_1.default.join(__dirname, '../data');
const SERVER_PORT = 5501;
try {
    const webServer = webserver_1.WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);
    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
//# sourceMappingURL=index.js.map