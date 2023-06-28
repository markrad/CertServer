"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const webserver_1 = require("./webserver");
// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// TODO: Add config file or parameters
// const ROOT_DIRECTORY = path.join(__dirname, '../data');
// const SERVER_PORT = 5501;
const defaultConfig = {
    port: 4141,
    root: path_1.default.join(__dirname, '../data'),
    C: 'USA',
    ST: 'Washington',
    L: 'Redmond',
    O: 'Microsoft',
    OU: 'CSS'
};
let config = {};
try {
    switch (process.argv.length) {
        case 2:
            config = defaultConfig;
            break;
        case 3:
            let options = require(process.argv[2]);
            config = Object.assign(Object.assign({}, defaultConfig), options);
            break;
        default:
            throw 'Invalid number of arguments - only a config file path is allowed';
    }
    const webServer = webserver_1.WebServer.createWebServer(config);
    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
//# sourceMappingURL=index.js.map