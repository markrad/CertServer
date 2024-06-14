export type Config = {
    certServer: {
        port: number;
        root: string;
        certificate?: string;
        key?: string;
        hashSecret?: string;
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
