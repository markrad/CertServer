"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const webserver_1 = require("./webserver");
// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
const ROOT_DIRECTORY = path_1.default.join(__dirname, '../data');
const SERVER_PORT = 5501;
const webServer = webserver_1.WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);
webServer.start();
//# sourceMappingURL=index.js.map