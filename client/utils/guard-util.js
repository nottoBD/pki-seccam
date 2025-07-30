import { pinnedFetch } from "@/cryptography/certificate";
import { getSessionKeys } from "@/utils/session-util";
import { getCryptoPackage, clearCryptoPackage } from "@/utils/transient-util";

export async function hardLogout(router) {
    try {
        localStorage.removeItem("token");
    } catch (_) {}

    try {
        const mod = await import("@/utils/session-util").catch(() => null);
        if (mod && typeof mod.clearSessionKeys === "function") {
            try {
                await mod.clearSessionKeys();
            } catch (_) {}
        } else {
            try {
                sessionStorage.removeItem("session_symm");
            } catch (_) {}
            try {
                sessionStorage.removeItem("session_hmac");
            } catch (_) {}
        }
    } catch (_) {}

    try {
        if (typeof clearCryptoPackage === "function") clearCryptoPackage();
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
    const token = (() => {
        try {
            return localStorage.getItem("token");
        } catch (_) {
            return null;
        }
    })();

    if (!token) {
        await hardLogout(router);
        return { ok: false };
    }

    const res = await pinnedFetch("/api/user/current", {
        headers: { Authorization: `Bearer ${token}` },
    }).catch(() => null);

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
