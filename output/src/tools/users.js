"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = __importDefault(require("bcrypt"));
const fs_1 = __importDefault(require("fs"));
const log4js = __importStar(require("log4js"));
const lokijs_1 = __importStar(require("lokijs"));
const minimist_1 = __importDefault(require("minimist"));
const logger = log4js.getLogger('users');
logger.level = log4js.levels.DEBUG;
function main(args) {
    return __awaiter(this, void 0, void 0, function* () {
        let options;
        let db;
        let runCmd = () => {
            let users;
            try {
                if (null == (users = db.getCollection('users'))) {
                    users = db.addCollection('users', {});
                }
                if (options.command === 'add') {
                    let user = users.findOne({ username: options.user });
                    if (user) {
                        logger.error(`User ${options.user} already exists`);
                        return;
                    }
                    users.insert({
                        username: options.user,
                        password: bcrypt_1.default.hashSync(options.password, 10),
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
                    if (bcrypt_1.default.compareSync(options.password, user.password)) {
                        logger.info(`User ${options.user} authenticated`);
                    }
                    else {
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
        };
        try {
            options = validateArgs(args);
            db = new lokijs_1.default(options.dbName, {
                autosave: false,
                autosaveInterval: 2000,
                adapter: new lokijs_1.LokiFsAdapter(),
                autoload: true,
                autoloadCallback: runCmd,
                verbose: true,
                persistenceMethod: 'fs'
            });
        }
        catch (err) {
            logger.error(err.message);
        }
    });
}
function validateArgs(args) {
    const validCommands = ['add', 'remove', 'list', 'test'];
    if (args.length === 0) {
        throw new Error('Usage: node users.js <db-name> <command> [--user <username>] [--password <password>]');
    }
    if (validCommands.indexOf(args[1]) === -1) {
        throw new Error(`Invalid command: ${args[1]}`);
    }
    if (fs_1.default.statSync(args[0]).isDirectory()) {
        throw new Error(`Database name must be a file: ${args[0]}`);
    }
    const mArgs = (0, minimist_1.default)(args);
    mArgs['user'] = mArgs['user'] || undefined;
    mArgs['password'] = mArgs['password'] || undefined;
    if (mArgs['user'] && typeof mArgs['user'] !== 'string')
        throw new Error('--user must be a string');
    if (mArgs['password'] && typeof mArgs['password'] !== 'string')
        throw new Error('--password must be a string');
    if (mArgs['_'].length > 2)
        throw new Error(`Too many arguments: ${mArgs['_'].join(' ')}`);
    if ((args[1] === 'add' || args[1] === 'test') && !mArgs['user'])
        throw new Error('Missing required argument: --user');
    if ((args[1] === 'add' || args[1] === 'test') && !mArgs['password'])
        throw new Error('Missing required argument: --password');
    if (args[1] === 'remove' && !mArgs['user'])
        throw new Error('Missing required argument: --user');
    return {
        dbName: args[0],
        command: args[1],
        user: mArgs['user'],
        password: mArgs['password']
    };
}
main(process.argv.slice(2)).catch(console.error);
//# sourceMappingURL=users.js.map