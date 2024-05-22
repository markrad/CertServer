import fs from 'fs';
import * as log4js from 'log4js';

import minimist from 'minimist';

type options = {
    dbName: string;
    removeOrphanKeys: boolean;
    removeOrphanCerts: boolean;
    renumber: boolean;
    force: boolean;
};

const logger = log4js.getLogger('dbcleanup');
logger.level = log4js.levels.DEBUG;

async function main(args: string[]): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        try {
            let options = validateArgs(args);
            const dbName = options.dbName;
            logger.info(`Cleaning up database ${dbName}`);
            logger.info('  Specified options:');
            logger.info(`    Remove orphan keys:  ${options.removeOrphanKeys? 'yes' : 'no'}`);
            logger.info(`    Remove orphan certs: ${options.removeOrphanCerts? 'yes' : 'no'}`);
            logger.info(`    Renumber:            ${options.renumber? 'yes' : 'no'}`);
            logger.info(`    Force:               ${options.force? 'yes' : 'no'}`);
            logger.info('Starting cleanup...');
            logger.info(`Backing up existing database ${dbName} to ${dbName}.bak`);
            fs.copyFileSync(dbName, `${dbName}.bak`, options.force? 0 : fs.constants.COPYFILE_EXCL);
            logger.info('Backup complete');
            resolve();
        } catch (err) {
            reject(err);
        }
    });
}

function validateArgs(args: string[]): options {

    const validArgs = ['remove-orphan-keys', 'remove-orphan-certs', 'renumber', 'force', '_'];

    if (args.length === 0) {
        throw new Error('Usage: node dbcleanup.js <db-name> [--remove-Orphan-Keys] [--remove-Orphan-Certs] [--renumber] [--force]');
    }

    if (fs.statSync(args[0]).isDirectory()) {
        throw new Error(`Database name must be a file: ${args[0]}`);
    }

    const mArgs = minimist(args);
    mArgs['remove-orphan-keys'] = mArgs['remove-orphan-keys'] || false;
    mArgs['remove-orphan-certs'] = mArgs['remove-orphan-certs'] || false;
    mArgs['renumber'] = mArgs['renumber'] || false;
    mArgs['force'] = mArgs['force'] || false;
    if (typeof mArgs['remove-orphan-keys'] !== 'boolean') throw new Error('--remove-orphan-keys does not accept an argument'); 
    if (typeof mArgs['remove-orphan-certs'] !== 'boolean') throw new Error('--remove-orphan-certs does not accept an argument');
    if (typeof mArgs['renumber'] !== 'boolean') throw new Error('--renumber does not accept an argument');
    if (typeof mArgs['force'] !== 'boolean') throw new Error('--force does not accept an argument');
    if (mArgs['_'].length > 1) throw new Error(`Too many arguments: ${mArgs['_'].join(' ')}`);
    if (Object.keys(mArgs).length > 5) throw new Error(`Unknown arguments: ${Object.keys(mArgs).filter((key) => validArgs.includes(key) === false).join(' ')}`);
    logger.debug(mArgs);

    return {
        dbName: mArgs['_'][0],
        removeOrphanKeys: mArgs['remove-orphan-keys'],
        removeOrphanCerts: mArgs['remove-orphan-certs'],
        renumber: mArgs['renumber'],
        force: mArgs['force'],
    };
}

main(process.argv.slice(2)).catch((err) => {
  logger.error(err.message);
  process.exit(1);
});