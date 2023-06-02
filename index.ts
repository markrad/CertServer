import { WebServer } from './webserver';

const ROOT_DIRECTORY = '/workspaces/typescript-node/data';
const SERVER_PORT = 5501;
const webServer = WebServer.createWebServer(SERVER_PORT, ROOT_DIRECTORY);

webServer.start()
