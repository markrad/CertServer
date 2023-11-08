import { GenerateCertRequest } from './GenerateCertRequest';

export type GenerateChildCertRequest = GenerateCertRequest & {
    password: string;
    signer: string;
    SANArray?: string[];
};
