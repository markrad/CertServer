import { CertificateRow } from "../webservertypes/CertificateRow";
import { CertificateUtil } from "./certificateUtil";

export class CertificateStores {
    private static _certificateDb: Collection<CertificateRow> = null;
    private static _certificatePath: string = null;

    public static Init(certificateDb: Collection<CertificateRow>, certificatePath: string) {
        if (certificateDb == null) throw new Error("Missing value for certficateDb");
        if (certificatePath == null) throw new Error("Missing value for certificatePath");

        CertificateStores._certificateDb = certificateDb;
        CertificateStores._certificatePath = certificatePath;
    }

    public static get CertificateDb(): Collection<CertificateRow> {
        if (CertificateStores._certificateDb == null) throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificateDb;
    }

    public static get CertificatePath(): string {
        if (CertificateStores._certificatePath == null) throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificatePath;
    }

    public static find(query?: LokiQuery<CertificateRow & LokiObj>): CertificateUtil[] {
        return CertificateStores.CertificateDb.find(query).map((r) => new CertificateUtil(r));
    }

    public static findOne(query?: LokiQuery<CertificateRow & LokiObj>): CertificateUtil {
        let r = CertificateStores.CertificateDb.findOne(query);
        return r == null ? null : new CertificateUtil(r);
    }

    public static bulkUpdate(query: LokiQuery<CertificateRow & LokiObj>, updateFunction: (obj: (CertificateRow & LokiObj)) => void): void {
        CertificateStores.CertificateDb.chain().find(query).update(updateFunction)
    }
}