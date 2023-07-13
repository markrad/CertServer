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
class EventWaiter {
    constructor() {
        this._resolvePtr = null;
        this._rejectPtr = null;
        this._promise = null;
        this._resolved = false;
        this._rejected = false;
        this.EventReset();
    }
    EventReset() {
        this._resolved = false;
        this._rejected = false;
        this._promise = new Promise((resolve, reject) => {
            this._resolvePtr = resolve;
            this._rejectPtr = reject;
        });
    }
    EventWait() {
        return __awaiter(this, void 0, void 0, function* () {
            return this._promise;
            // return new Promise<void>((resolve, reject) => {
            //     this._promise.then(() => resolve(), (err: any) => reject(err));
            // });
        });
    }
    EventSet() {
        this._resolved = true;
        this._resolvePtr();
    }
    EventError(err) {
        this._rejected = true;
        this._rejectPtr(err);
    }
    get EventIsPending() {
        return !(this._resolved || this._rejected);
    }
    get EventIsResolved() {
        return this._resolved;
    }
    get EventIsRejected() {
        return this._rejected;
    }
}
exports.EventWaiter = EventWaiter;
//# sourceMappingURL=eventWaiter.js.map