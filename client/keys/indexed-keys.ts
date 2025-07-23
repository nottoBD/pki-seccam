import {IDBPDatabase, openDB} from 'idb';

const DB_NAME = 'seccam-keystore';
const STORE = 'keys';
const STORE_PUB = 'pub';

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDB() {
    if (typeof window === 'undefined')
        throw new Error('IndexedDB is not available in a Node/SSR context');

    if (!dbPromise) {
        dbPromise = openDB(DB_NAME, 1, {
            upgrade(db) {
                db.createObjectStore(STORE);
                db.createObjectStore(STORE_PUB);
            },
        });

        if (navigator.storage?.persist) navigator.storage.persist();
    }
    return dbPromise;
}

export async function saveKey(deviceId: string, key: CryptoKey) {
    const db = await getDB();
    await db.put(STORE, key, deviceId);
}

export async function getKey(deviceId: string): Promise<CryptoKey | undefined> {
    const db = await getDB();
    return db.get(STORE, deviceId);
}

export async function deleteKey(deviceId: string) {
    const db = await getDB();
    await db.delete(STORE, deviceId);
}

export async function savePublic(deviceId: string, pem: string) {
    await (await getDB()).put(STORE_PUB, pem, deviceId);
}

export async function getPublic(deviceId: string): Promise<string | undefined> {
    return (await getDB()).get(STORE_PUB, deviceId);
}


