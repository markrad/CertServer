"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WSManager = void 0;
const log4js_1 = require("log4js");
const ws_1 = require("ws");
let logger = (0, log4js_1.getLogger)("WSManager");
class WSManager {
    static upgrade(request, socket, head) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve, reject) => {
                try {
                    logger.info("WSManager initializing");
                    WSManager._ws.handleUpgrade(request, socket, head, ws => {
                        ws.send('Connected');
                        logger.debug('WebSocket client connected');
                        resolve();
                    });
                }
                catch (err) {
                    logger.error(`Error initializing WSManager: ${err}`);
                    reject(err);
                }
            });
        });
    }
    static broadcast(data) {
        let msg = JSON.stringify(data.normalize());
        logger.debug('Updates: ' + msg);
        WSManager._ws.clients.forEach((client) => {
            if (client.readyState === ws_1.OPEN) {
                client.send(msg, (err) => {
                    if (err) {
                        logger.error(`Failed to send to client`);
                    }
                    else {
                        logger.debug('Sent update to client');
                    }
                });
            }
        });
    }
}
exports.WSManager = WSManager;
WSManager._ws = new ws_1.Server({ noServer: true });
//# sourceMappingURL=wsmanager.js.map