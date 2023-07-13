import { access, constants } from 'fs/promises';

export async function exists(filename: string): Promise<boolean> {
    return new Promise<boolean>(async (resolve, _reject) => {
        try {
            await access(filename, constants.F_OK);
            resolve(true);
        }
        catch (err) {
            resolve(false);
        }
    });
}