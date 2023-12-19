import { access, constants } from 'fs/promises';

/**
 * Async version of the fs exists function that is not provided by the standard node package
 * 
 * @param filename The name of the file to check for existence
 * @returns True if it exists otherwise false
 */
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