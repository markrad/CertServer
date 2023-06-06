import path from 'path';
import { WebServer } from './webserver';

// const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
const ROOT_DIRECTORY = path.join(__dirname, '../data');
const SERVER_PORT = 5501;
const webServer = WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);

webServer.start()
