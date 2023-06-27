import path from 'path';
import { WebServer } from './webserver';

// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// TODO: Add config file or parameters
// const ROOT_DIRECTORY = path.join(__dirname, '../data');
// const SERVER_PORT = 5501;

const defaultConfig: any = {
    port: 4141,
    root:path.join(__dirname, '../data'),
    C: 'USA',
    S: 'Washington',
    L: 'Redmond',
    O: 'Microsoft',
    OU: 'CSS'
};

let config: any = {};

try {
    switch (process.argv.length) {
        case 2:
            config = defaultConfig;
            break;
        case 3:
            let options = require(process.argv[2]);
            config = { ...defaultConfig, ...options };
            break;
        default:
            throw 'Invalid number of arguments - only a config file path is allowed'
    }

    const webServer = WebServer.createWebServer(config);

    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
