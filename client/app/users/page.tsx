"use client";
import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
  importPrivateKey,
  importPublicKey
} from '@/cryptography/asymmetric';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {pinnedFetch} from "@/cryptography/certificate";


export default function EditUsers() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [name, setName] = useState("");
    const [trustedUsers, setTrustedUsers] = useState([]);
    const [errorMessage, setErrorMessage] = useState(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();
    const [alert, setAlert] = useState(null);

    useEffect(() => {
        const token = localStorage.getItem("token");
        (async () => {
            try {
                if (!token) {
                    setIsCheckingAuth(false);
                    return router.push("/");
                }

                const response = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`},
                });
                if (response.ok) {
                    const data = await response.json();
                    setIsAuthenticated(true);
                    setName(data.isTrustedUser ? data.fullname : data.username);
                    if (data.isTrustedUser) {
                        return router.push("/home-trust");
                    }
                    fetchTrustedUsers();
                } else {
                    router.push("/");
                }
            } catch (error) {
                console.error("Error verifying authentication:", error);
                router.push("/");
            } finally {
                setIsCheckingAuth(false);
            }
        })();
    }, []);

    const fetchTrustedUsers = async () => {
        setLoading(true);
        setErrorMessage(null);

        try {
            const token = localStorage.getItem("token");
            const response = await pinnedFetch("/api/user/trusted/list", {
                headers: {Authorization: `Bearer ${token}`},
            });
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
        const {default: forge} = await import('node-forge');
        try {
            const token = localStorage.getItem("token");

            const symKeyResponse = await pinnedFetch("/api/user/getSymmetric", {  // Adjusted URL
                headers: {Authorization: `Bearer ${token}`},
            });
            const symKeyData = await symKeyResponse.json();
            const encryptedSymmetricKey = symKeyData.encryptedSymmetricKey;
            const privateKey = localStorage.getItem(`${symKeyData.username}_private_key`);

            if (!privateKey) {
                throw new Error("Private key not found for the user.");
            }

            const importedPrivateKey = await importPrivateKey(privateKey, "decrypt");
            const symmetricKeyBase64 = await decryptWithPrivateKey(encryptedSymmetricKey, importedPrivateKey);
            const cert = forge.pki.certificateFromPem(trustedUser.certificate);

            const spki = forge.pki.publicKeyToSubjectPublicKeyInfo(cert.publicKey);
            const pubKeyPem = forge.pki.publicKeyInfoToPem(spki);

            const trustedUserPubKey = await importPublicKey(pubKeyPem, 'encrypt');
            const encryptedKey = await encryptWithPublicKey(symmetricKeyBase64, trustedUserPubKey);

            const sharedResponse = await pinnedFetch("/api/user/trusted/share", {
                method: 'POST',
                headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
                body: JSON.stringify({
                    trustedUser: trustedUser._id,
                    encrypted_symmetric_key: encryptedKey
                }),
            });
            if (sharedResponse.ok) {
                const sharedResponseData = await sharedResponse.json();
                setAlert({
                    type: "success",
                    message: sharedResponseData.message
                });
                fetchTrustedUsers();
            } else {
                throw new Error("Share failed");
            }
        } catch (error) {
            console.error("Error trusting user:", error);
            setErrorMessage("Failed to trust the user.");
        }
    };

    const handleUntrust = async (trustedUserId) => {
        try {
            const token = localStorage.getItem("token");
            const response = await pinnedFetch("/api/user/trusted/unshare", {
                method: 'POST',
                headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
                body: JSON.stringify({ trustedUser: trustedUserId }),
            });
            if (response.ok) {
                const data = await response.json();
                setAlert({
                    type: "success",
                    message: data.message
                });
                fetchTrustedUsers();
            } else {
                throw new Error("Unshare failed");
            }
        } catch (error) {
            console.error("Error untrusting user:", error);
            setErrorMessage("Failed to untrust the user.");
        }
    };

    const sharedUsers = trustedUsers.filter(u => u.isShared);
    const availableUsers = trustedUsers.filter(u => !u.isShared);

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
