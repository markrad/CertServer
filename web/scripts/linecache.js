class LineCache {
    _certs = new Map();
    _keys = new Map();
    _onAdd = [];
    _onUpdate = [];
    _onDelete = [];
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
            console.log('Cache disconnected from WebSocket - reconnecting');
            connectWebSocket();
        }
        let wsonerror = (e) => {
            console.log('Cache WebSocket error: ' + e.message);
        }
        let wsonmessage = (e) => {
            if (e.data != 'Connected') {
                this._processUpdates(JSON.parse(e.data));
            }
        }
        connectWebSocket();
    }

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

    getCertBrief(id) {
        return this._certs.get(id);
    }

    getKeyBrief(id) {
        return this._keys.get(id);
    }

    async getCertDetail(id) {
        let certDetails = this._certs.get(parseInt(id));
        if (certDetails.details === undefined) {
            let details = await this._ajaxCall('GET', `/certDetails?id=${id}`, null);
            certDetails['details'] = details;
        }

        return certDetails.details;
    }

    async getKeyDetail(id) {
        let keyDetails = this._keys.get(parseInt(id));
        if (keyDetails.details === undefined) {
            let details = await this._ajaxCall('GET', `/keyDetails?id=${id}`, null);
            keyDetails['details'] = details;
        }

        return keyDetails.details;
    }

    async deleteKey(id) {
        return this._ajaxCall('DELETE', `/deleteKey?id=${id}`, null);
    }

    async deleteCert(id) {
        return this._ajaxCall('DELETE', `/deleteCert?id=${id}`, null);
    }

    setAddHandler(func) {
        this._onAdd.push(func);
    }

    setUpdateHandler(func) {
        this._onUpdate.push(func);
    }

    setDeleteHandler(func) {
        this._onDelete.push(func);
    }

    removeAddHandler(func) {
        let r = this._onAdd.find(func);
        if (r != -1) delete this._onAdd[r];
    }

    removeUpdateHandler(func) {
        let r = this._onUpdate.find(func);
        if (r != -1) delete this._onUpdate[r];
    }

    removeDeleteHandler(func) {
        let r = this._onDelete.find(func);
        if (r != -1) delete this._onDelete[r];
    }

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

    async _getFromServer(url) {
        return this._ajaxCall('GET', url, null);
    }

    async postToServer(url, data) {
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

    async _ajaxCall(verb, url, data) {
        return new Promise((resolve, reject) => {
            $.ajax({
                url: url,
                method: verb,
                processData: false,
                contentType: false,
                data: data,
                error: (xhr, _msg, err) => {
                    reject(new Error(`${err}: ${xhr.responseJSON.error}`));
                },
                success: async (result, _status) => {
                    resolve(result);
                }
            });
        });
    }
}
