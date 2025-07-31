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
