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

    public static remove(dbRow: DBVersionRow & LokiObj): DBVersionRow {
        return DbStores.dbDb.remove(dbRow);
    }
}