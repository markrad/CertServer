export class EventWaiter {
    private _resolvePtr: Function = null;
    private _rejectPtr: Function = null;
    private _promise: Promise<void> = null;
    private _resolved = false;
    private _rejected = false;
    constructor() {
        this.EventReset();
    }

    EventReset(): void {
        this._resolved = false;
        this._rejected = false;
        this._promise = new Promise((resolve, reject) => {
            this._resolvePtr = resolve;
            this._rejectPtr = reject;
        });
    }

    async EventWait(timeout?: number): Promise<void> {
        if (!timeout) {
            return this._promise;
        }
        else {
            return Promise.race([
                this._promise,
                new Promise<void>((_resolve, reject) => setTimeout(() => reject(new Error('Timed out')))),
            ]);
        }
    }

    EventSet() {
        this._resolved = true;
        this._resolvePtr();
    }

    EventError(err?: any) {
        this._rejected = true;
        this._rejectPtr(err);
    }

    get EventIsPending(): boolean {
        return !(this._resolved || this._rejected);
    }

    get EventIsResolved(): boolean {
        return this._resolved;
    }

    get EventIsRejected(): boolean {
        return this._rejected;
    }
}
