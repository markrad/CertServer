import crypto from 'crypto';

import { DBVersionRow } from "./DBVersionRow";

export class DbStores {
    private static _dbDb: Collection<DBVersionRow> = null;

    public static init(dbDb: Collection<DBVersionRow>) {
        if (dbDb == null) throw new Error("Missing value for dbDb");

        DbStores._dbDb = dbDb;
    }

    public static get dbDb(): Collection<DBVersionRow> {
        if (DbStores._dbDb == null) throw new Error("DbStores had not been initialized");
        return DbStores._dbDb;
    }

    public static find(query?: LokiQuery<DBVersionRow & LokiObj>): (DBVersionRow & LokiObj)[] {
        return DbStores.dbDb.find(query);   //.map((r) => new CertificateUtil(r));
    }

    private static insert(dbRow: DBVersionRow): DBVersionRow & LokiObj {
        return DbStores.dbDb.insert(dbRow) as (DBVersionRow & LokiObj);
    }

    // public static update(dbRow: DBVersionRow & LokiObj): DBVersionRow & LokiObj {
    //     return DbStores.dbDb.update(dbRow) as (DBVersionRow & LokiObj);
    // }

    public static initialize(version: number, authenticationState: boolean, KeyEncryptionState: boolean): void {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            DbStores.insert({ 
                version: version, 
                keySecret: crypto.randomBytes(32).toString('hex'),
                passwordSecret: crypto.randomBytes(32).toString('hex'),
                authenticationState: authenticationState,
                keyEncryptionState: KeyEncryptionState
            });
        }
        else {
            throw new Error("DbStores has already been initialized");
        }
    }
    public static updateVersion(version: number): void {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found - database not initialized");
        }
        else {
            row.version = version;
            DbStores.dbDb.update(row);
        }
    }

    public static getKeySecret(): string {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.keySecret;
    }

    public static getPasswordSecret(): string {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.passwordSecret;
    }   

    public static getAuthenticationState(): boolean {   
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.authenticationState;
    }

    public static getKeyEncryptionState(): boolean {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            return null;
        }
        return row.keyEncryptionState;
    }

    public static setKeyEncryptionState(state: boolean): void {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found - database not initialized");
        }
        else {
            row.keyEncryptionState = state;
            DbStores.dbDb.update(row);
        }
    }

    public static remove(dbRow: DBVersionRow & LokiObj): DBVersionRow {
        return DbStores.dbDb.remove(dbRow);
    }
}