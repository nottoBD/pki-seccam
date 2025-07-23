const SYMM = 'session_symm';
const HMAC = 'session_hmac';


export function setSessionKeys(symmBase64: string, hmacBase64: string) {
    sessionStorage.setItem(SYMM, symmBase64);
    sessionStorage.setItem(HMAC, hmacBase64);
}

export function getSessionKeys() {
    return {
        symmBase64: sessionStorage.getItem(SYMM),
        hmacBase64: sessionStorage.getItem(HMAC),
    };
}

export function clearSessionKeys() {
    sessionStorage.removeItem(SYMM);
    sessionStorage.removeItem(HMAC);
}
