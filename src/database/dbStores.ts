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

    public static insert(dbRow: DBVersionRow): DBVersionRow & LokiObj {
        return DbStores.dbDb.insert(dbRow) as (DBVersionRow & LokiObj);
    }

    public static update(dbRow: DBVersionRow & LokiObj): DBVersionRow & LokiObj {
        return DbStores.dbDb.update(dbRow) as (DBVersionRow & LokiObj);
    }

    public static updateVersion(version: number): void {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            DbStores.insert({ version: version, keySecret: null });
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

    public static updateKeySecret(keySecret: string): void {
        const row = DbStores.dbDb.findOne({});
        if (row == null) {
            throw new Error("DBVersionRow not found");
        }
        else {
            row.keySecret = keySecret;
            DbStores.dbDb.update(row);
        }
    }

    public static remove(dbRow: DBVersionRow & LokiObj): DBVersionRow {
        return DbStores.dbDb.remove(dbRow);
    }
}