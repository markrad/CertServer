/**
 * Caches certificate and key details to save server round-trips.
 * 
 * @class Detail cache
 */
class LineCache {
    _certs = new Map();
    _keys = new Map();
    _onAdd = [];
    _onUpdate = [];
    _onDelete = [];
    /**
     * Constructs a new detail cache and connects to the server's WebSocket.
     */
    constructor() {
        let connectWebSocket = () => {
            let wsURL = (window.location.protocol == 'https:' ? 'wss://' : 'ws://') +
                window.location.hostname +
                ':' + window.location.port;
            const ws = new WebSocket(wsURL);
            ws.onopen = wsonopen;
            ws.onclose = wsonclose;
            ws.onerror = wsonerror;
            ws.onmessage = wsonmessage;
        }
        let wsonopen = (e) => {
            console.log('Cache connected to WebSocket');
        }
        let wsonclose = (e) => {
            console.warn('Cache disconnected from WebSocket - reconnecting');
            connectWebSocket();
        }
        let wsonerror = (e) => {
            console.error('Cache WebSocket error: ' + e.message);
        }
        let wsonmessage = (e) => {
            if (e.data != 'Connected') {
                this._processUpdates(JSON.parse(e.data));
            }
        }
        connectWebSocket();
    }

    /**
     * Get all the briefs for the keys or certificates.
     * 
     * @param {'root' | 'intermediate' | 'leaf' | 'key'} type 
     * @returns {Promise<{ name: string, type: 'root' | 'intermediate' | 'leaf' | 'keys', id: number }>} Line details
     */
    async getLineHeaders(type) {
        return new Promise(async (resolve, reject) => {
            try {
                let res = await this._getFromServer(`/certList?type=${type}`);
                res.files.forEach((file) => type === 'key' ? this._keys.set(file.id, file) : this._certs.set(file.id, file));
                resolve(res.files);
            }
            catch (err) {
                reject(err);
            }
        })
    }

    /**
     * Returns the brief for the requested certificate.
     * 
     * @param {number} id Id of the requested certificate
     * @returns {{ name: string, type: 'root' | 'intermediate' | 'leaf', id: number }}
     */
    getCertBrief(id) {
        return this._certs.get(id);
    }

    /**
     * Returns the brief for the requested key.
     * 
     * @param {number} id Id of the requested key
     * @returns {{ name: string, type: 'key', id: number }}
     */
    getKeyBrief(id) {
        return this._keys.get(id);
    }

    /**
     * Get the certificate details. If it is not cached then it will be requested from the server and cached for later use.
     * 
     * @param {string | number} id Identity of requested certificate
     * @returns {{
     *      id: number,
     *      certType: 'root' | 'intermediate' | 'leaf',
     *      fingerprint: string, 
     *      fingerprint256: string,
     *      issuer: { C: string, ST: string, L: string, O: string, OU: string, CN: string },
     *      keyId: number,
     *      name: string,
     *      serialNumber: string,
     *      signerId: number,
     *      subject: { C: string, ST: string, L: string, O: string, OU: string, CN: string },
     *      tags: string[],
     *      validFrom: string,
     *      validTo: string
     * }} certificate details
     */
    async getCertDetail(id) {
        let certDetails = this._certs.get(parseInt(id));
        if (certDetails.details === undefined) {
            let details = await this._ajaxCall('GET', `/certDetails?id=${id}`, null);
            certDetails['details'] = details;
        }

        return certDetails.details;
    }

    /**
     * Get the key details. If it is not cached then it will be requested from the server and cached for later use.
     * 
     * @param {string | number} id Identity of requested key
     * @returns {{
     *      id: number,
     *      certPair: string,
     *      encrypted: boolean,
     *      name: string
     * }} key details
     */
    async getKeyDetail(id) {
        let keyDetails = this._keys.get(parseInt(id));
        if (keyDetails.details === undefined) {
            let details = await this._ajaxCall('GET', `/keyDetails?id=${id}`, null);
            keyDetails['details'] = details;
        }

        return keyDetails.details;
    }

    /**
     * Request the server to delete this certificate
     * 
     * @param {string | number} id id of certificate to delete
     * @returns {{ message: string } | Error } Success message or error
     */
    async deleteCert(id) {
        return this._ajaxCall('DELETE', `/deleteCert?id=${id}`, null);
    }

    /**
     * Request the server to delete this key
     * 
     * @param {string | number} id id of key to delete
     * @returns {{ message: string } | Error } Success message or error
     */
    async deleteKey(id) {
        return this._ajaxCall('DELETE', `/deleteKey?id=${id}`, null);
    }

    /**
     * Add a new add handler to the collection
     * 
     * @param {(type: number, name: string) => void} func 
     */
    setAddHandler(func) {
        if (typeof func !== 'function') throw new Error('Set handler argument must be a function');
        this._onAdd.push(func);
    }

    /**
     * Add a new update handler to the collection
     * 
     * @param {(type: number, name: string) => void} func 
     */
    setUpdateHandler(func) {
        if (typeof func !== 'function') throw new Error('Set handler argument must be a function');
        this._onUpdate.push(func);
    }

    /**
     * Add a new delete handler to the collection
     * 
     * @param {(type: number) => void} func 
     */
    setDeleteHandler(func) {
        if (typeof func !== 'function') throw new Error('Set handler argument must be a function');
        this._onDelete.push(func);
    }

    /**
     * Remove an add handler from the collection
     * 
     * @param {(type: number, name: string) => void} func 
     */
    removeAddHandler(func) {
        let r = this._onAdd.find(func);
        if (r != -1) delete this._onAdd[r];
        else throw new Error('Function not found');
    }

    /**
     * Remove an update handler from the collection
     * 
     * @param {(type: number, name: string) => void} func 
     */
    removeUpdateHandler(func) {
        let r = this._onUpdate.find(func);
        if (r != -1) delete this._onUpdate[r];
        else throw new Error('Function not found');
    }

    /**
     * Remove a delete handler from the collection
     * 
     * @param {(type: number) => void} func 
     */
    removeDeleteHandler(func) {
        let r = this._onDelete.find(func);
        if (r != -1) delete this._onDelete[r];
        else throw new Error('Function not found');
    }

    /**
     * Process updates sent by the server via the WebSocket connection. Calls the appropriate callback functions for each entry in the arrays added, updated, and deleted.
     * 
     * @param {{ 
     *      name: string,
     *      added: { type: 1 | 2 | 3 | 4, id: number}[],
     *      updated: { type: 1 | 2 | 3 | 4, id: number}[],
     *      deleted: { type: 1 | 2 | 3 | 4, id: number}[]
     * }} opResult the results of changes to the database
     */
    _processUpdates(opResult) {
        console.log('certcache received: ' + JSON.stringify(opResult));
        opResult.added.forEach(async (res) => {
            let entry;
            if (res.type == 4) {
                entry = await this._getFromServer(`/api/keyname?id=${res.id}`);
                entry['tags'] = [];
                this._keys.set(res.id, entry);
            }
            else {
                entry = await this._getFromServer(`/api/certname?id=${res.id}`);
                entry['tags'] = [];
                this._certs.set(res.id, entry);
            }
            for (let f in this._onAdd) {
                this._onAdd[f](res.type, entry);
            }
        });
        opResult.updated.forEach(async (res) => {
            let entry;
            if (res.type == 4) {
                entry = await this._getFromServer(`/api/keyname?id=${res.id}`);
                entry['tags'] = [];
                this._keys.set(res.id, entry);
            }
            else {
                entry = await this._getFromServer(`/api/certname?id=${res.id}`);
                this._certs.set(res.id, entry);
            }
            for (let f in this._onUpdate) {
                this._onUpdate[f](res.type, entry);
            }
        });
        opResult.deleted.forEach(async (res) => {
            if (res.type == 4) {
                this._keys.delete(res.id);
            }
            else {
                this._certs.delete(res.id);
            }
            for (let f in this._onDelete) {
                this._onDelete[f](res.type, res.id);
            }
        })
    }

    /**
     * Request data from the server.
     * 
     * @param {string} url URL to POST to
     * @returns {Promise<any>} server response
     */
    async _getFromServer(url) {
        return this._ajaxCall('GET', url, null);
    }

    /**
     * Post data to the server.
     * 
     * @param {string} url URL to POST to
     * @param {string} data post data
     * @returns {Promise<{ message: string }>} server response
     */
    async _postToServer(url, data) {
        return this._ajaxCall('POST', url, data);
        // return new Promise((resolve, reject) => {
        //     $.ajax({
        //         url: url,
        //         method: 'POST',
        //         processData: false,
        //         contentType: false,
        //         data: data,
        //         error: (xhr, _msg, err) => {
        //             reject(new Error(err + ': ' + JSON.parse(xhr.responseText).error));
        //         },
        //         success: async (result, status) => {
        //             resolve();
        //         }
        //     });
        // });
    }

    /**
     * Sends an ajax request to the server.
     * 
     * @param {string} verb HTTP verb to use
     * @param {string} url URL to connect to
     * @param {string?} data to send or null 
     * @returns {Promise<{message: string}>} response from the server
     */
    async _ajaxCall(verb, url, data) {
        return new Promise((resolve, reject) => {
            $.ajax({
                url: url,
                method: verb,
                processData: false,
                contentType: false,
                data: data,
                error: (xhr, _msg, err) => {
                    reject(xhr.responseJSON);
                },
                success: async (result, _status) => {
                    resolve(result);
                }
            });
        });
    }
}
