export type GenerateCertRequest = {
    country: string;
    state: string;
    location: string;
    organization: string;
    unit: string;
    commonName: string;
    validFrom: string;
    validTo: string;
};
