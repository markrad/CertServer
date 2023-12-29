"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const deepmerge_1 = __importDefault(require("deepmerge"));
const webserver_1 = require("./webserver");
const js_yaml_1 = require("js-yaml");
const fs_1 = require("fs");
const defaultConfig_1 = require("./defaultConfig");
let config = defaultConfig_1.defaultConfig;
try {
    switch (process.argv.length) {
        case 2:
            // Use default config
            break;
        case 3:
            // Merge specified options from config file with default config
            let options = ((0, js_yaml_1.load)((0, fs_1.readFileSync)((path_1.default.resolve(process.argv[2])), { encoding: 'utf8' })));
            config = (0, deepmerge_1.default)(defaultConfig_1.defaultConfig, options);
            break;
        default:
            // Error exit
            throw 'Invalid number of arguments - only a config file path is allowed';
    }
    if (config.certServer.subject.C.length != 2) {
        throw new Error(`Invalid country code ${config.certServer.subject.C} - must be two characters`);
    }
    const webServer = webserver_1.WebServer.createWebServer(config);
    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
//# sourceMappingURL=index.js.map