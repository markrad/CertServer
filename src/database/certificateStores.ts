import { CertificateRow } from "./CertificateRow";
import { CertificateUtil } from "./certificateUtil";

export class CertificateStores {
    private static _certificateDb: Collection<CertificateRow> = null;
    private static _certificatePath: string = null;

    public static init(certificateDb: Collection<CertificateRow>, certificatePath: string) {
        if (certificateDb == null) throw new Error("Missing value for certficateDb");
        if (certificatePath == null) throw new Error("Missing value for certificatePath");

        CertificateStores._certificateDb = certificateDb;
        CertificateStores._certificatePath = certificatePath;
    }

    public static get certificateDb(): Collection<CertificateRow> {
        if (CertificateStores._certificateDb == null) throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificateDb;
    }

    public static get certificatePath(): string {
        if (CertificateStores._certificatePath == null) throw new Error("CertificateStores had not been initialized");
        return CertificateStores._certificatePath;
    }

    public static find(query?: LokiQuery<CertificateRow & LokiObj>): CertificateUtil[] {
        return CertificateStores.certificateDb.find(query).map((r) => new CertificateUtil(r));
    }

    public static findOne(query?: LokiQuery<CertificateRow & LokiObj>): CertificateUtil {
        let r = CertificateStores.certificateDb.findOne(query);
        return r == null ? null : new CertificateUtil(r);
    }

    public static bulkUpdate(query: LokiQuery<CertificateRow & LokiObj>, updateFunction: (obj: (CertificateRow & LokiObj)) => void): void {
        CertificateStores.certificateDb.chain().find(query).update(updateFunction)
    }
}