import { access, constants } from 'fs/promises';

export async function exists(filename: string): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
        try {
            access(filename, constants.F_OK);
            resolve(true);
        }
        catch (err) {
            reject(false);
        }
    });
}