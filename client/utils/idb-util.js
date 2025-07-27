const { openDB } = require('idb');

const DB_NAME = 'seccam-keystore';
const STORE_USER = 'user-keys';
const STORE_ORG_KEY = 'org-keys';
const STORE_ORG_CERT = 'org-certs';

let dbPromise = null;

function getDB() {
    if (typeof window === 'undefined')
        throw new Error('IndexedDB is not available in a Node/SSR context');

    if (!dbPromise) {
        dbPromise = openDB(DB_NAME, 2, {
            upgrade(db) {
                if (!db.objectStoreNames.contains(STORE_USER)) db.createObjectStore(STORE_USER);
                if (!db.objectStoreNames.contains(STORE_ORG_KEY)) db.createObjectStore(STORE_ORG_KEY);
                if (!db.objectStoreNames.contains(STORE_ORG_CERT)) db.createObjectStore(STORE_ORG_CERT);
            },
        });
        if (navigator.storage?.persist) navigator.storage.persist();
    }
    return dbPromise;
}


exports.saveUserKeyPackage = async function(username, data) {
    const db = await getDB();
    await db.put(STORE_USER, data, username);
}

exports.getUserKeyPackage = async function(username) {
    const db = await getDB();
    return db.get(STORE_USER, username);
}

exports.saveOrgKeyPair = async function(orgKey, jwk, publicPem) {
    const db = await getDB();
    await db.put(STORE_ORG_KEY, {jwk, publicPem}, orgKey);
}

exports.getOrgKeyPair = async function(orgKey) {
    const db = await getDB();
    return db.get(STORE_ORG_KEY, orgKey);
}

exports.saveOrgCert = async function(orgKey, certPem) {
    const db = await getDB();
    await db.put(STORE_ORG_CERT, certPem, orgKey);
}

exports.getOrgCert = async function(orgKey) {
    const db = await getDB();
    return db.get(STORE_ORG_CERT, orgKey);
}