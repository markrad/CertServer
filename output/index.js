"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const webserver_1 = require("./webserver");
const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
const SERVER_PORT = 5501;
const webServer = webserver_1.WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);
webServer.start();
//# sourceMappingURL=index.js.map