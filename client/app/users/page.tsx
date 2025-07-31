"use client";
import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
} from '@/cryptography/asymmetric';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {getCryptoPackage} from "@/utils/transient-util";
import { pinnedFetch, importPublicKeyFromCertificate } from "@/cryptography/certificate";
import {assertAuthAndContext, hardLogout} from "@/utils/guard-util";


export default function EditUsers() {
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [name, setName] = useState("");
    const [trustedUsers, setTrustedUsers] = useState([]);
    const [errorMessage, setErrorMessage] = useState(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();
    const [alert, setAlert] = useState(null);

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router, "normal");
                if (!result.ok) return;
                setName(result.user.username);
                await fetchTrustedUsers();
            } catch (error) {
                console.error("Error verifying authentication:", error);
                await hardLogout(router);
            } finally {
                setIsCheckingAuth(false);
            }
        })();
    }, [router]);

    const fetchTrustedUsers = async () => {
        setLoading(true);
        setErrorMessage(null);

        try {
            const response = await pinnedFetch("/api/keywrap");
            if (response.ok) {
                setTrustedUsers(await response.json());
            } else {
                setErrorMessage("Failed to fetch trusted users.");
            }
        } catch (error) {
            console.error("Error fetching trusted users:", error);
            setErrorMessage("An error occurred while fetching trusted users.");
        } finally {
            setLoading(false);
        }
    };

    const handleTrust = async (trustedUser) => {
        setErrorMessage(null);
        try {
            if (!trustedUser?._id) throw new Error("Selected trusted user is invalid.");
            if (!trustedUser?.certificate) throw new Error("Trusted user's certificate is missing.");

            const decryptedPackage = getCryptoPackage();
            if (!decryptedPackage?.privateKeyJwk) {
                throw new Error("Crypto package not loaded. Please log in again.");
            }

            const keysResp = await pinnedFetch("/api/user/getSymmetric");
            if (!keysResp.ok) {
                throw new Error(`Unable to retrieve symmetric keys (HTTP ${keysResp.status}).`);
            }
            const { encryptedSymmetricKey, encryptedHmacKey } = await keysResp.json();
            if (!encryptedSymmetricKey || !encryptedHmacKey) {
                throw new Error("Server did not return both encrypted keys.");
            }

            const privateKeyJwkCopy = { ...decryptedPackage.privateKeyJwk };
            delete privateKeyJwkCopy.alg;
            delete privateKeyJwkCopy.key_ops;

            const importedPrivateKey = await window.crypto.subtle.importKey(
                "jwk",
                privateKeyJwkCopy,
                { name: "RSA-OAEP", hash: "SHA-256" },
                true,
                ["decrypt"]
            );

            const symmetricKeyBase64 = await decryptWithPrivateKey(encryptedSymmetricKey, importedPrivateKey);
            const hmacKeyBase64 = await decryptWithPrivateKey(encryptedHmacKey, importedPrivateKey);

            const trustedUserPubKey = await importPublicKeyFromCertificate(trustedUser.certificate, "encrypt");

            const wrappedSymmetricKey = await encryptWithPublicKey(symmetricKeyBase64, trustedUserPubKey);
            const wrappedHmacKey = await encryptWithPublicKey(hmacKeyBase64, trustedUserPubKey);

            const shareResp = await pinnedFetch("/api/keywrap", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    trusted_user_id: trustedUser._id,
                    wrapped_symmetric_key: wrappedSymmetricKey,
                    wrapped_hmac_key: wrappedHmacKey,
                }),
            });

            if (!shareResp.ok) {
                const errText = await shareResp.text().catch(() => "");
                throw new Error(`Failed to store wrapped keys. ${errText || ""}`.trim());
            }

            setAlert({ type: "success", message: "User trusted successfully!" });
            await fetchTrustedUsers();
        } catch (error) {
            console.error("Error trusting user:", error);
            setAlert(null);
            setErrorMessage(`Failed to trust the user: ${error?.message || "Unknown error"}`);
        }
    };


    const handleUntrust = async (trustedUserId) => {
        try {
            const response = await pinnedFetch(`/api/keywrap/${trustedUserId}`, {
                method: 'DELETE',
                headers: {"Content-Type": "application/json"},
            });

            if (!response.ok) throw new Error("Failed to remove trust relationship.");

            setAlert({ type: "success", message: "User untrusted successfully." });
            fetchTrustedUsers();
        } catch (error) {
            console.error("Error untrusting user:", error);
            setErrorMessage("Failed to untrust the user: " + error.message);
        }
    };

    const byName = (a, b) => a.username.localeCompare(b.username);
    const sharedUsers = trustedUsers.filter(u => u.isShared).sort(byName);
    const availableUsers = trustedUsers.filter(u => !u.isShared).sort(byName);


    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Trusted Users" width={420}>
                    {loading && <p>Loading...</p>}

                    {alert && (
                        <p>
                            {alert.type === "error" ? "Error" : "Success"}: {alert.message}
                        </p>
                    )}

                    <h3>Trusted Users</h3>
                    {!loading && sharedUsers.length > 0 ? (
                        <ul style={{marginBottom: 12}}>
                            {sharedUsers.map((u) => (
                                <li
                                    key={u._id}
                                    style={{display: "flex", justifyContent: "space-between"}}
                                >
                                    <b>{u.username}</b>
                                    <button onClick={() => handleUntrust(u._id)}>
                                        Untrust
                                    </button>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        !loading && <p>No trusted users yet.</p>
                    )}

                    <h3>Available Trusted Users</h3>
                    {!loading && availableUsers.length > 0 ? (
                        <ul style={{marginBottom: 12}}>
                            {availableUsers.map((u) => (
                                <li
                                    key={u._id}
                                    style={{display: "flex", justifyContent: "space-between"}}
                                >
                                    <b>{u.username}</b>
                                    <button onClick={() => handleTrust(u)}>
                                        Trust
                                    </button>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        !loading && <p>No available trusted users.</p>
                    )}
                </Window98>
            </main>
        </>
    );
}
