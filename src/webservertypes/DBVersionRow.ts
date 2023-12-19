/**
 * Represents the database row that contains the database version number. There should only ever be one of these rows.
 */
export type DBVersionRow = {
    /** Database version number */
    version: number;
};
