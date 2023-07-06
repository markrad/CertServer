import path from 'path';
import deepmerge from 'deepmerge';
import { WebServer } from './webserver';

// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// const ROOT_DIRECTORY = path.join(__dirname, '../data');
// const SERVER_PORT = 5501;

const defaultConfig: any = {
    certServer: {
        certificate: null,
        key: null,
        port: 4141,
        root: './data',
        subject: {
            C: 'USA',
            ST: 'Washington',
            L: 'Redmond',
            O: 'None',
            OU: 'None'
        }
    }
};

let config: any = {};

try {
    switch (process.argv.length) {
        case 2:
            config = defaultConfig;
            break;
        case 3:
            let options = require('yaml-reader').read(path.resolve(process.argv[2]));
            config = deepmerge(defaultConfig, options);
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
