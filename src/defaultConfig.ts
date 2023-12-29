import { Config } from './webservertypes/Config';

export const defaultConfig: Config = {
    certServer: {
        certificate: null,
        key: null,
        port: 4141,
        root: './data',
        subject: {
            C: 'US',
            ST: 'Washington',
            L: 'Redmond',
            O: 'None',
            OU: 'None'
        }
    }
};
