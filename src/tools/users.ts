import bcrypt from 'bcrypt'
import fs from 'fs';
import * as log4js from 'log4js';
import loki, { Collection, LokiFsAdapter } from 'lokijs'

import minimist from 'minimist';
import { UserRow } from '../database/UserRow';

const logger = log4js.getLogger('users');
logger.level = log4js.levels.DEBUG;

type options = {
    dbName: string;
    command: 'add' | 'remove' | 'list' | 'test';
    user?: string;
    password?: string;
};

async function main(args: string[]) {
    let options: options;
    let db: loki;
    let runCmd: () => void = () => {
        let users: Collection<UserRow>;
        try {
            if (null == (users = db.getCollection<UserRow>('users'))) {
                users = db.addCollection<UserRow>('users', {});
            }
            if (options.command === 'add') {
                let user = users.findOne({ username: options.user });
                if (user) {
                    logger.error(`User ${options.user} already exists`);
                    return;
                }
                users.insert({
                    username: options.user,
                    password: bcrypt.hashSync(options.password, 10),
                    lastSignedIn: null,
                    tokenExpiration: null
                });
                logger.info(`User ${options.user} added`);
            }
            else if (options.command === 'test') {
                let user = users.findOne({ username: options.user });
                if (!user) {
                    logger.error(`User ${options.user} not found`);
                    return;
                }
                if (bcrypt.compareSync(options.password, user.password)) {
                    logger.info(`User ${options.user} authenticated`);
                } else {
                    logger.error(`User ${options.user} not authenticated`);
                }
            }
            else if (options.command === 'remove') {
                let user = users.findOne({ username: options.user });
                if (!user) {
                    logger.error(`User ${options.user} not found`);
                    return;
                }
                users.remove(user);
                logger.info(`User ${options.user} removed`);
            } 
            else if (options.command === 'list') {
                let userList = users.find();
                if (userList.length === 0) {
                    logger.info('No users found');
                    return;
                }
                userList.forEach((user) => {
                    logger.info(`User: ${user.username} Last signed in: ${user.lastSignedIn != null ? user.lastSignedIn : 'Never'} Token expiration: ${user.tokenExpiration != null ? user.tokenExpiration : 'None'}`);
                });
            }
        }
        catch (err) {
            logger.error(err.message);
        }
        finally {
            if (db) {
                db.saveDatabase();
                db.close();
            }
        }
    }
    try {
        options = validateArgs(args);
        db = new loki(options.dbName, {
            autosave: false,
            autosaveInterval: 2000,
            adapter: new LokiFsAdapter(),
            autoload: true,
            autoloadCallback: runCmd,
            verbose: true,
            persistenceMethod: 'fs'
        });
    }
    catch (err) {
        logger.error(err.message);
    }
}

function validateArgs(args: string[]): options {
    const validCommands = ['add', 'remove', 'list', 'test'];

    if (args.length === 0) {
        throw new Error('Usage: node users.js <db-name> <command> [--user <username>] [--password <password>]');
    }

    if (validCommands.indexOf(args[1]) === -1) {
        throw new Error(`Invalid command: ${args[1]}`);
    }

    if (fs.statSync(args[0]).isDirectory()) {
        throw new Error(`Database name must be a file: ${args[0]}`);
    }

    const mArgs = minimist(args);
    mArgs['user'] = mArgs['user'] || undefined;
    mArgs['password'] = mArgs['password'] || undefined;

    if (mArgs['user'] && typeof mArgs['user'] !== 'string') throw new Error('--user must be a string');
    if (mArgs['password'] && typeof mArgs['password'] !== 'string') throw new Error('--password must be a string');
    if (mArgs['_'].length > 2) throw new Error(`Too many arguments: ${mArgs['_'].join(' ')}`);
    if ((args[1] === 'add' || args[1] === 'test') && !mArgs['user']) throw new Error('Missing required argument: --user');
    if ((args[1] === 'add' || args[1] === 'test') && !mArgs['password']) throw new Error('Missing required argument: --password');
    if (args[1] === 'remove' && !mArgs['user']) throw new Error('Missing required argument: --user');

    return {
        dbName: args[0],
        command: args[1] as options['command'],
        user: mArgs['user'],
        password: mArgs['password']
    };
}

main(process.argv.slice(2)).catch(console.error);
