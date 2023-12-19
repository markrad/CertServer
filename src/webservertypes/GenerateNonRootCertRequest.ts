import { GenerateCertRequest } from './GenerateCertRequest';

export type GenerateNonRootCertRequest = GenerateCertRequest & {
    password: string;
    signer: string;
    SANArray?: string[];
};
