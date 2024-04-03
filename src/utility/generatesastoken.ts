import crypto from 'crypto';

/**
 * Type to hold the individual parts of the connection string.
 */
type hubCredentials = {
    hostName: string,
    sharedAccessKey: string,
    sharedAccessKeyName: string
}

export type ConnectionInfo = {
    url: string,
    SASToken: string
}

export function getSASToken(connectionString: string): ConnectionInfo {
    try {
        let credentials = parseConnectionString(connectionString);
        return {url: `https://${credentials.hostName}`, SASToken: generateSASToken(credentials, 60) };
    }
    catch (e) {
        console.log(e.message);
        throw e;
    }

}

/**
 * Parse the connection string into individual elements. The userId will be prepared ready to pass to the MQTT client.
 * 
 * @param connectionString The device's connection string
 * @returns Individual elements of the connection string.
 */
function parseConnectionString(connectionString: string): hubCredentials {
    let res: hubCredentials = { hostName: null, sharedAccessKey: null, sharedAccessKeyName: null };

    try {
        let parts = connectionString.split(';').sort((l, r) => l.localeCompare(r));
        res.hostName = parts[0].slice('HostName='.length);
        res.sharedAccessKey = parts[1].slice('SharedAccessKey='.length)
        res.sharedAccessKeyName = parts[2].slice('SharedAccessKeyName='.length);

        if (!res.hostName || !res.sharedAccessKey || !res.sharedAccessKeyName) {
            throw new Error('Invalid connection string');
        }

        return res;
    }
    catch (e) {
        throw e;
    }
}

/**
 * Generate a new SAS token for IoT hub authentication.
 * 
 * @param credentials Elements from the connection string required to generate a SAS token
 * @param expiry Number of minutes the SAS token is good for
 * @returns SAS token
 */
function generateSASToken(credentials: hubCredentials, expiry: number): string {
    // let resourceUri = encodeURIComponent(`${credentials.hostName}/devices/${credentials.deviceId}`);
    let expires = Math.ceil((Date.now() / 1000) + expiry * 60);
    let toSign = `${credentials.hostName}\n${expires}`;
    let hmac = crypto.createHmac('sha256', Buffer.from(credentials.sharedAccessKey, 'base64'));
    hmac.update(toSign);
    let base64UriEncoded = encodeURIComponent(hmac.digest('base64'));
    let token = `SharedAccessSignature sr=${credentials.hostName}&sig=${base64UriEncoded}&se=${expires}&skn=${credentials.sharedAccessKeyName}`;

    return token;
}
