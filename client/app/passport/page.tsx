"use client";
import React, { useEffect, useMemo, useState } from "react";
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {
    decryptCryptoPassportLogin,
    encryptCryptoPassportRegistration,
    reEncryptCryptoPassport,
} from "@/cryptography/symmetric";
import { getCryptoPackage } from "@/utils/transient-util";
import { publicKeyPemFromCertificate } from "@/cryptography/certificate";
import { assertAuthAndContext } from "@/utils/guard-util";
import {useRouter} from "next/navigation";


export default function ChangePassportPassword() {
    const [loadedPackage, setLoadedPackage] = useState<any | null>(null);
    const [file, setFile] = useState<File | null>(null);
    const [currentPwd, setCurrentPwd] = useState("");
    const [newPwd, setNewPwd] = useState("");
    const [confirmPwd, setConfirmPwd] = useState("");
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [reencrypting, setReencrypting] = useState(false);
    const [message, setMessage] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router);
                setIsAuthenticated(result.ok);
            } catch {
                setIsAuthenticated(false);
            }
        })();
    }, [router]);


    useEffect(() => {
        try {
            const pkg = getCryptoPackage?.();
            if (pkg && typeof pkg === "object") {
                setLoadedPackage(pkg);
            }
        } catch {
        }
    }, []);

    const canUseLoaded = useMemo(() => !!loadedPackage, [loadedPackage]);

    function normalizeDecryptedPackage(pkg: any) {
        const out: any = { ...pkg };

        if (!out.privateKeyJwk && out.userPrivateKeyJwk) {
            out.privateKeyJwk = out.userPrivateKeyJwk;
        }

        try {
            if (out.userCertificate && !out.userPublicKeyPem) {
                out.userPublicKeyPem = publicKeyPemFromCertificate(out.userCertificate);
            }
        } catch {}

        try {
            if (out.orgCertificate && !out.orgPublicKeyPem) {
                out.orgPublicKeyPem = publicKeyPemFromCertificate(out.orgCertificate);
            }
        } catch {}

        return out;
    }

    const handleVerifyUpload = async () => {
        setError(null);
        setMessage(null);
        if (!file) return setError("Please choose a .sec.json file.");
        if (!currentPwd) return setError("Enter your current password.");

        setVerifying(true);
        try {
            let obj = await decryptCryptoPassportLogin(file, currentPwd);
            if (!obj?.privateKeyJwk && !obj?.userPrivateKeyJwk) {
                throw new Error("This package doesn't look valid (missing private key).");
            }
            obj = normalizeDecryptedPackage(obj);
            setLoadedPackage(obj);
            setMessage("Package verified. You can now set a new password.");
        } catch (e:any) {
            setError(e?.message || "Failed to decrypt the package. Check the current password.");
        } finally {
            setVerifying(false);
        }
    };

    const handleReencrypt = async () => {
        setError(null);
        setMessage(null);

        if (newPwd.length < 12) return setError("Use at least 12 characters for the new password.");
        if (newPwd !== confirmPwd) return setError("New password and confirmation do not match.");
        if (!loadedPackage && !file) return setError("Load a package first (from session or upload).");

        setReencrypting(true);
        try {
            let blob: Blob;

            if (canUseLoaded) {
                blob = await encryptCryptoPassportRegistration(loadedPackage, newPwd);
            } else {
                if (!file) throw new Error("No file selected.");
                if (!currentPwd) throw new Error("Current password is required.");
                blob = await reEncryptCryptoPassport(file, currentPwd, newPwd);
            }

            await decryptCryptoPassportLogin(blob, newPwd);

            const suggestedName =
                (file?.name?.replace(/\.sec\.json$/i, "") || "crypto-passport") + ".sec.json";

            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = suggestedName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);

            // scrub memory
            setCurrentPwd("");
            setNewPwd("");
            setConfirmPwd("");
            setMessage("Package re-encrypted. A new file has been downloaded.");
        } catch (e:any) {
            setError(e?.message || "Re-encryption failed.");
        } finally {
            setReencrypting(false);
        }
    };

    return (
        <>
            {isAuthenticated && <Navbar98 />}
            <main style={{ display: "flex", justifyContent: "center", marginTop: 40 }}>
                <Window98 title="Change Crypto Package Password" width={480}>
                    <p style={{ marginTop: 0 }}>
                        Re-encrypt your <code>Crypto Passport</code> here (<code>.sec.json</code>).
                    </p>

                    {canUseLoaded ? (
                        <div style={{ padding: "8px", background: "#eef8ee", borderRadius: 6, marginBottom: 12 }}>
                            <b>Using package from current session.</b>
                        </div>
                    ) : (
                        <>
                            <label>Upload</label>
                            <input
                                type="file"
                                accept="application/json,.json"
                                onChange={(e) => setFile(e.target.files?.[0] || null)}
                            />
                            <label style={{ marginTop: 8 }}>Current password</label>
                            <input
                                type="password"
                                value={currentPwd}
                                onChange={(e) => setCurrentPwd(e.target.value)}
                            />
                            <div style={{ marginTop: 8 }}>
                                <button disabled={verifying || !file || !currentPwd} onClick={handleVerifyUpload}>
                                    {verifying ? "Verifying..." : "Verify package"}
                                </button>
                            </div>
                            <hr />
                        </>
                    )}

                    <label>New password</label>
                    <input
                        type="password"
                        value={newPwd}
                        onChange={(e) => setNewPwd(e.target.value)}
                        placeholder="Min 12 characters"
                    />

                    <label style={{ marginTop: 8 }}>Confirm new password</label>
                    <input
                        type="password"
                        value={confirmPwd}
                        onChange={(e) => setConfirmPwd(e.target.value)}
                    />

                    <div style={{ marginTop: 12 }}>
                        <button disabled={reencrypting || (!canUseLoaded && !loadedPackage)} onClick={handleReencrypt}>
                            {reencrypting ? "Re-encrypting..." : "Re-encrypt & Download"}
                        </button>
                    </div>

                    {message && <p style={{ color: "green" }}>{message}</p>}
                    {error && <p style={{ color: "crimson" }}>{error}</p>}
                </Window98>
            </main>
        </>
    );
}
