/**
 * The query type that must be name or id
 */
export type QueryType = {} & ({ name?: string, id: string; } | { name: string, id?: string });
