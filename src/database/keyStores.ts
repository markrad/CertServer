import { pki } from "node-forge";
import { PrivateKeyRow } from "./PrivateKeyRow";
import { KeyUtil } from "./keyUtil";
// import { CertificateUtil } from "./certificateUtil";
// import { CertificateStores } from "./certificateStores";

export class KeyStores {
    private static _privateKeyDb: Collection<PrivateKeyRow> = null;
    private static _privateKeyPath: string = null;

    public static init(privateKeyDb: Collection<PrivateKeyRow>, privateKeyPath: string) {
        if (privateKeyDb == null) throw new Error("Missing value for privateKeyDb");
        if (privateKeyPath == null) throw new Error("Missing value for privateKeyPath");

        KeyStores._privateKeyDb = privateKeyDb;
        KeyStores._privateKeyPath = privateKeyPath;
    }

    public static get keyDb(): Collection<PrivateKeyRow> {
        if (KeyStores._privateKeyDb == null) throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyDb;
    }

    public static get keyPath(): string {
        if (KeyStores._privateKeyPath == null) throw new Error("KeyStores had not been initialized");
        return KeyStores._privateKeyPath;
    }

    public static find(query?: LokiQuery<PrivateKeyRow & LokiObj>): KeyUtil[] {
        return KeyStores.keyDb.find(query).map((r) => new KeyUtil(r));
    }

    public static findOne(query?: LokiQuery<PrivateKeyRow & LokiObj>): KeyUtil {
        let r = KeyStores.keyDb.findOne(query);
        return r == null? null : new KeyUtil(r);
    }

    public static remove(id: number) {
        KeyStores.keyDb.remove(id);
    }

    public static isIdentical(k: KeyUtil): KeyUtil {
        let keyIn: pki.rsa.PublicKey = k.setRsaPublicKey();
        let allKeys = KeyStores.find();

        for (let iKey in allKeys) {
            if (allKeys[iKey].isIdentical(keyIn)) {
                return allKeys[iKey];
            }
        }

        return null;
    }

    // public static setCertificateKeyPair(k: KeyUtil): CertificateUtil {
    //     let certs = CertificateStores.find({ keyId: null });
    //     let check: CertificateUtil;

    //     for (let c in certs) {
    //         if ((check = k.isCertificateKeyPair(certs[c])))
    //             return check;
    //     }

    //     return null;
    // }
}