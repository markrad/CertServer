import { getLogger } from "log4js";
import { Server, OPEN } from "ws";
import http from "http";
import internal from "stream";
import { OperationResult } from "../webservertypes/OperationResult";

let logger = getLogger("WSManager");

export class WSManager {
    private static _ws = new Server({ noServer: true });
    public static async upgrade(request: http.IncomingMessage, socket: internal.Duplex, head: Buffer): Promise<void> {
        return new Promise<void>((resolve, reject) => {
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
    }
    public static broadcast(data: OperationResult): void {
        let msg = JSON.stringify(data.normalize());
        logger.debug('Updates: ' + msg);

        WSManager._ws.clients.forEach((client) => {
            if (client.readyState === OPEN) {
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