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
exports.EventWaiter = void 0;
/**
 * Allows an asynchronous function to await for a completion in another asynchronous function.
 * See test below for example.
 */
class EventWaiter {
    /**
     * Constructs an instance of this class
     * @constructor
     */
    constructor() {
        this._resolvePtr = null;
        this._rejectPtr = null;
        this._promise = null;
        this._resolved = false;
        this._rejected = false;
        this._version = 0;
        this.EventReset();
    }
    /**
     * This will reset the instance so that it is no longer complete. If a timeout is used with EventWait then the return value should be
     * passed to EventSet. This will prevent a EventSet setting the class after that event has already timed out.
     * @returns a unique number that can be used in EventSet
     */
    EventReset() {
        this._resolved = false;
        this._rejected = false;
        this._promise = new Promise((resolve, reject) => {
            this._resolvePtr = resolve;
            this._rejectPtr = reject;
        });
        return ++this._version;
    }
    /**
     * Waits for event completion.
     * @param timeout Optional. The number of milliseconds to wait for completion. Default is forever.
     * @returns A void Promise to use with await
     */
    EventWait(timeout) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!timeout) {
                return this._promise;
            }
            else {
                return Promise.race([
                    this._promise,
                    new Promise((_resolve, reject) => setTimeout(() => reject(new Error('Timed out')), timeout)),
                ]);
            }
        });
    }
    /**
     *
     * @param version This value is returned by EventReset. Use it to ensure you set the current event rather than one that timed out.
     */
    EventSet(version) {
        if ((version && version == this._version) || !version) {
            this._resolved = true;
            this._resolvePtr();
        }
    }
    /**
     * Call when the action failed
     * @param err Cause the promise to be rejected
     */
    EventError(err) {
        // TODO This should have a version parameter too
        this._rejected = true;
        this._rejectPtr(err);
    }
    /***
     * Returns true if the event is still pending
     */
    get EventIsPending() {
        return !(this._resolved || this._rejected);
    }
    /**
     * Returns true if the event has been resolved
     */
    get EventIsResolved() {
        return this._resolved;
    }
    /**
     * Returns true if the event has been rejected
     */
    get EventIsRejected() {
        return this._rejected;
    }
}
exports.EventWaiter = EventWaiter;
/*
async function test() {
    let ew = new EventWaiter();

    // Fails
    try {
        let version = ew.EventReset();
        console.log(`${new Date().toTimeString()} should fail`);
        setTimeout(() => ew.EventSet(version), 5100);
        await ew.EventWait(5000);
        console.log(new Date().toTimeString() + ' done')
    }
    catch (err) {
        console.error(new Date().toTimeString() + ' ' + err.message);
    }

    // Works
    try {
        let version = ew.EventReset();
        console.log(new Date().toTimeString() + ' should work');
        setTimeout(() => ew.EventSet(version), 4900);
        await ew.EventWait(5000);
        console.log(new Date().toTimeString() + ' done')
    }
    catch (err) {
        console.error(new Date().toTimeString() + ' ' + err.message);
    }

}

console.log(new Date().toTimeString() + ' start');
// test();
*/ 
//# sourceMappingURL=eventWaiter.js.map