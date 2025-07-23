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
    const [orgs, setOrgs] = useState([]);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();
    const [alert, setAlert] = useState<{ type: "success" | "error"; message: string } | null>(null);

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
                        return router.push("/hometrusted");
                    }
                    fetchOrgs();
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

    const fetchOrgs = async () => {
        setLoading(true);
        setErrorMessage(null);

        try {
            const token = localStorage.getItem("token");
            const response = await pinnedFetch("/api/organizations/list", {
                headers: {Authorization: `Bearer ${token}`},
            });
            if (response.ok) {
                setOrgs(await response.json());
            } else {
                setErrorMessage("Failed to fetch users.");
            }
        } catch (error) {
            console.error("Error fetching users:", error);
            setErrorMessage("An error occurred while fetching your users.");
        } finally {
            setLoading(false);
        }
    };

    const handleOrgSelect = async (org: string) => {
        const {default: forge} = await import('node-forge');
        try {
            const token = localStorage.getItem("token");

            const symKeyResponse = await pinnedFetch("/getSymmetric", {
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
            const cert = forge.pki.certificateFromPem(org.certificate);

            const spki = forge.pki.publicKeyToSubjectPublicKeyInfo(cert.publicKey);
            const pubKeyPem = forge.pki.publicKeyInfoToPem(spki);

            const orgPubKey = await importPublicKey(pubKeyPem, 'encrypt');
            const encryptedKey = await encryptWithPublicKey(symmetricKeyBase64, orgPubKey);

            const sharedResponse = await pinnedFetch("/api/organizations/share", {
                method: 'POST',
                headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
                body: JSON.stringify({
                    organization: org._id,
                    encrypted_symmetric_key: encryptedKey
                }),
            });
            if (sharedResponse.ok) {
                const sharedResponseData = await sharedResponse.json();
                setAlert({
                    type: "success",
                    message: sharedResponseData.message
                });
                fetchOrgs();
            }
        } catch (error) {
            console.error("Error encrypting/decrypting keys:", error);
            setErrorMessage("Failed to encrypt/decrypt the keys.");
        }
    };

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Trusted Companies" width={420}>
                    {loading && <p>Loading..</p>}

                    {alert && (
                        <p>
                            {alert.type === "error" ? "Error" : "Success"}: {alert.message}
                        </p>
                    )}

                    {!loading && orgs.length > 0 ? (
                        <ul style={{marginBottom: 12}}>
                            {orgs.map((o) => (
                                <li
                                    key={o._id}
                                    style={{display: "flex", justifyContent: "space-between"}}
                                >
                                    <b>{o.name} ({o.country})</b>
                                    <button onClick={() => handleOrgSelect(o)}>
                                        Share With!
                                    </button>
                                </li>
                            ))}
                        </ul>
                    ) : (
                        !loading && <p>No Organization left to trust.</p>
                    )}
                </Window98>
            </main>
        </>
    );
}
