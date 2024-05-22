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
const fs_1 = __importDefault(require("fs"));
const log4js = __importStar(require("log4js"));
const minimist_1 = __importDefault(require("minimist"));
const logger = log4js.getLogger('dbcleanup');
logger.level = log4js.levels.DEBUG;
function main(args) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            try {
                let options = validateArgs(args);
                const dbName = options.dbName;
                logger.info(`Cleaning up database ${dbName}`);
                logger.info('  Specified options:');
                logger.info(`    Remove orphan keys:  ${options.removeOrphanKeys ? 'yes' : 'no'}`);
                logger.info(`    Remove orphan certs: ${options.removeOrphanCerts ? 'yes' : 'no'}`);
                logger.info(`    Renumber:            ${options.renumber ? 'yes' : 'no'}`);
                logger.info(`    Force:               ${options.force ? 'yes' : 'no'}`);
                logger.info('Starting cleanup...');
                logger.info(`Backing up existing database ${dbName} to ${dbName}.bak`);
                fs_1.default.copyFileSync(dbName, `${dbName}.bak`, options.force ? 0 : fs_1.default.constants.COPYFILE_EXCL);
                logger.info('Backup complete');
                resolve();
            }
            catch (err) {
                reject(err);
            }
        });
    });
}
function validateArgs(args) {
    const validArgs = ['remove-orphan-keys', 'remove-orphan-certs', 'renumber', 'force', '_'];
    if (args.length === 0) {
        throw new Error('Usage: node dbcleanup.js <db-name> [--remove-Orphan-Keys] [--remove-Orphan-Certs] [--renumber] [--force]');
    }
    if (fs_1.default.statSync(args[0]).isDirectory()) {
        throw new Error(`Database name must be a file: ${args[0]}`);
    }
    const mArgs = (0, minimist_1.default)(args);
    mArgs['remove-orphan-keys'] = mArgs['remove-orphan-keys'] || false;
    mArgs['remove-orphan-certs'] = mArgs['remove-orphan-certs'] || false;
    mArgs['renumber'] = mArgs['renumber'] || false;
    mArgs['force'] = mArgs['force'] || false;
    if (typeof mArgs['remove-orphan-keys'] !== 'boolean')
        throw new Error('--remove-orphan-keys does not accept an argument');
    if (typeof mArgs['remove-orphan-certs'] !== 'boolean')
        throw new Error('--remove-orphan-certs does not accept an argument');
    if (typeof mArgs['renumber'] !== 'boolean')
        throw new Error('--renumber does not accept an argument');
    if (typeof mArgs['force'] !== 'boolean')
        throw new Error('--force does not accept an argument');
    if (mArgs['_'].length > 1)
        throw new Error(`Too many arguments: ${mArgs['_'].join(' ')}`);
    if (Object.keys(mArgs).length > 5)
        throw new Error(`Unknown arguments: ${Object.keys(mArgs).filter((key) => validArgs.includes(key) === false).join(' ')}`);
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
//# sourceMappingURL=dbcleanup.js.map