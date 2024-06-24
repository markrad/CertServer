/**
 * Represents the configuration options for the CertServer.
 */
export type Config = {
    certServer: {
        /** The port the CertServer will listen on - default 4141 */
        port: number;
        /** The path to the root directory of the CertServer - required */
        root: string;
        /** Certificate used for https encryption - default none */
        certificate?: string;
        /** Private key used for https encryption - default none */
        key?: string;
        /** When true, keys will be encrypted at rest - default false */
        encryptKeys?: boolean;
        /** When true, authentication will be used - default false */
        useAuthentication?: boolean;
        /** The secret used to encrypt keys at rest - default none <this will be deprecated> */
        keySecret?: string;
        subject: {
            C: string;
            ST: string;
            L: string;
            O: string;
            OU: string;
        };
    };
};
