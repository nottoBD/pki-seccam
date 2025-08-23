/**
 * Client-side route guard and session validator.
 * This utility ensures that a user not only has a valid auth token but also the necessary cryptographic context in place (like encryption keys in session or a decrypted private key package) before allowing them to access certain pages.
 * It provides a `hardLogout` function to clear all session data and keys, and an `assertAuthAndContext` function that is used to protect Next.js pages by redirecting or logging out users who don’t meet the security context requirements.
 */


import { pinnedFetch } from "@/cryptography/certificate";
import { getSessionKeys, clearSessionKeys } from "@/utils/session-util";
import { getCryptoPackage, clearCryptoPackage } from "@/utils/transient-util";


export async function hardLogout(router) {
    try {
        await pinnedFetch('/api/user/logout', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (_) {}

    try {
        await clearSessionKeys();
    } catch (_) {
        try {
            sessionStorage.removeItem("session_symm");
            sessionStorage.removeItem("session_hmac");
        } catch (_) {}
    }

    try {
        clearCryptoPackage();
    } catch (_) {}

    router.replace("/");
}

function hasNormalSessionKeys() {
    try {
        const { symmBase64, hmacBase64 } = getSessionKeys();
        if (symmBase64 && hmacBase64) return true;
    } catch (_) {}
    try {
        const s = sessionStorage.getItem("session_symm");
        const h = sessionStorage.getItem("session_hmac");
        return Boolean(s && h);
    } catch (_) {
        return false;
    }
}

function hasTrustedCryptoPackage() {
    try {
        const pkg = getCryptoPackage();
        return Boolean(pkg && pkg.privateKeyJwk);
    } catch (_) {
        return false;
    }
}


/**
 * The `assertAuthAndContext` function is called whenever a protected page loads to verify the user’s authentication and cryptographic setup.
 * It first checks if we have either a normal session (symmetric & HMAC keys for regular users) or a trusted user’s crypto package in memory. If not, it quickly returns `ok: false`.
 * Next, it calls the backend’s `/api/user/current` endpoint (using a pinned HTTPS request) to ensure the auth cookie is valid and to get the latest user info.
 * If the backend says the session is invalid, we trigger a hard logout (clearing keys and forcing a redirect to login).
 * We also enforce context: if a normal user somehow tries to access a trusted-only page or vice versa, we redirect them to the appropriate homepage.
 * Finally, for a trusted user, we ensure their private key package is still loaded (since without it they cannot decrypt anything); for a normal user, we ensure their symmetric keys are present.
 * If any of these checks fail, we log the user out; if all checks pass, we return `{ ok: true, user }` to let the page render.
 */

export async function assertAuthAndContext(router, target = "either") {
    const currentPath = typeof window !== 'undefined' ? window.location.pathname.split('?')[0] : '';
    const hasSession = hasNormalSessionKeys() || hasTrustedCryptoPackage();
    if (['/login', '/register', '/passport', '/verify-email', '/api-docs'].includes(currentPath)) {
        if (!hasSession) {
            return { ok: false };
        }
        const res = await pinnedFetch("/api/user/current").catch(() => null);
        if (res && res.ok) {const user = await res.json().catch(() => null);
            if (user) {
                return { ok: true, user };
            }
        }
        return { ok: false };
    }

    const res = await pinnedFetch("/api/user/current").catch(() => null);

    if (!res || !res.ok) {
        await hardLogout(router);
        return { ok: false };
    }

    const user = await res.json().catch(() => null);
    if (!user) {
        await hardLogout(router);
        return { ok: false };
    }

    if (target === "normal" && user.isTrustedUser) {
        router.replace("/home-trust");
        return { ok: false };
    }
    if (target === "trusted" && !user.isTrustedUser) {
        router.replace("/home");
        return { ok: false };
    }

    if (user.isTrustedUser) {
        if (!hasTrustedCryptoPackage()) {
            console.warn("[guard] Missing trusted crypto package (transient).");
            await hardLogout(router);
            return { ok: false };
        }
    } else {
        if (!hasNormalSessionKeys()) {
            console.warn("[guard] Missing normal user session keys.");
            await hardLogout(router);
            return { ok: false };
        }
    }

    return { ok: true, user };
}
