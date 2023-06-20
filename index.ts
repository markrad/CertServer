import path from 'path';
import { WebServer } from './webserver';

// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
// TODO: Add config file or parameters
const ROOT_DIRECTORY = path.join(__dirname, '../data');
const SERVER_PORT = 5501;

try {
    const webServer = WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);

    webServer.start();
}
catch (err) {
    console.error(`Unable to start webserver: ${err}`);
}
