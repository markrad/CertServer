import path from 'path';
import deepmerge from 'deepmerge';
import { WebServer } from './webserver';
import { Config } from './webservertypes/Config';
import { load } from 'js-yaml';
import { readFileSync } from 'fs';
import { defaultConfig } from './defaultConfig';

let config: Config = defaultConfig;

try {
    switch (process.argv.length) {
        case 2:
            // Use default config
            break;
        case 3:
            // Merge specified options from config file with default config
            let options: Config = (load(readFileSync((path.resolve(process.argv[2])), { encoding: 'utf8' }))) as Config;
            config = deepmerge(defaultConfig, options);
            break;
        default:
            // Error exit
            throw 'Invalid number of arguments - only a config file path is allowed'
    }

    const webServer = WebServer.createWebServer(config);

    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
