"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const deepmerge_1 = __importDefault(require("deepmerge"));
const webserver_1 = require("./webserver");
// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// const ROOT_DIRECTORY = path.join(__dirname, '../data');
// const SERVER_PORT = 5501;
const defaultConfig = {
    certServer: {
        certificate: null,
        key: null,
        port: 4141,
        root: './data',
        subject: {
            C: 'US',
            ST: 'Washington',
            L: 'Redmond',
            O: 'None',
            OU: 'None'
        }
    }
};
let config = {};
try {
    switch (process.argv.length) {
        case 2:
            config = defaultConfig;
            break;
        case 3:
            let options = require('yaml-reader').read(path_1.default.resolve(process.argv[2]));
            config = (0, deepmerge_1.default)(defaultConfig, options);
            break;
        default:
            throw 'Invalid number of arguments - only a config file path is allowed';
    }
    if (config.certServer.subject.C.length != 2) {
        throw new Error(`Invalid country code ${config.C} - must be two characters`);
    }
    const webServer = webserver_1.WebServer.createWebServer(config);
    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
//# sourceMappingURL=index.js.map