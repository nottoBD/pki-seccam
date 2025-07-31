"use client";
import React, {useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {decryptDataChunk, importKey} from '@/cryptography/symmetric';
import {base64ToArrayBuffer} from '@/cryptography/asymmetric';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {formatDate} from "@/utils/date-util";
import {pinnedFetch} from "@/cryptography/certificate";
import {getSessionKeys} from "@/utils/session-util";
import {unwrapKeysWithPrivateKey} from '@/handlers/crypto-hdlr';
import {getCryptoPackage} from "@/utils/transient-util";
import {assertAuthAndContext, hardLogout} from "@/utils/guard-util";


export default function PlaybackPage() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isTrustedUser, setIsTrustedUser] = useState(false);
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [name, setName] = useState("");
    const [videos, setVideos] = useState([]);
    const [selectedVideo, setSelectedVideo] = useState(null);
    const [decryptedVideoUrl, setDecryptedVideoUrl] = useState(null);
    const [errorMessage, setErrorMessage] = useState(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const result = await assertAuthAndContext(router, "either");
                if (!result.ok) return;
                setIsAuthenticated(true);
                setIsTrustedUser(!!result.user.isTrustedUser);
                setName(result.user.username);
            } catch {
                await hardLogout(router);
            } finally {
                setIsCheckingAuth(false);
            }
        })();
    }, [router]);

    const fetchUserVideos = async () => {
        setLoading(true);
        try {
            const endpoint = isTrustedUser ? "/api/video/trustedList" : "/api/video/list";
            const response = await pinnedFetch(endpoint);
            if (response.ok) {
                const data = await response.json();
                setVideos(isTrustedUser ? data.flatMap(u => u.videos.map(v => ({...v, owner_username: u.username}))) : data.videos);
            } else {
                setErrorMessage("Failed to fetch videos.");
            }
        } catch (error) {
            setErrorMessage("An error occurred while fetching your videos.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (isAuthenticated) fetchUserVideos();
    }, [isAuthenticated]);

    const handleVideoSelect = async (video) => {
        setSelectedVideo(video);
        setLoading(true);
        setErrorMessage(null);

        try {
            let symmetricKey;
            if (isTrustedUser) {
                const wrapResp = await pinnedFetch(`/api/keywrap/${video.owner_username}/keys`);
                if (!wrapResp.ok) throw new Error("Access denied.");

                const { wrapped_symmetric_key, wrapped_hmac_key } = await wrapResp.json();
                const pkg = getCryptoPackage();
                if (!pkg?.privateKeyJwk) {
                    throw new Error("Crypto package not loaded (transient). Please log in again.");
                }
                let unwrap;
                try {
                    unwrap = await unwrapKeysWithPrivateKey(wrapped_symmetric_key, wrapped_hmac_key, pkg.privateKeyJwk);
                } catch (e) {
                    setErrorMessage(`Key unwrap failed: ${e.message}`);
                    setLoading(false);
                    return;
                }
                ({ symmetricKey } = unwrap);
            } else {
                const { symmBase64 } = getSessionKeys();
                symmetricKey = await importKey(base64ToArrayBuffer(symmBase64));
            }

            const chunksResp = await pinnedFetch(`/api/video/${video.name}/${video.owner_username || name}/chunks`);
            if (!chunksResp.ok) throw new Error("Failed to fetch video chunks.");
            const chunks = await chunksResp.json();

            let decryptedChunks;
            try {
                decryptedChunks = await Promise.all(chunks.map(c => decryptDataChunk(c.chunk, symmetricKey)));
            } catch (e) {
                setErrorMessage(`AES-GCM decrypt failed: ${e.message}`);
                setLoading(false);
                return;
            }

            const combinedBlob = new Blob(decryptedChunks, { type: "video/webm" });
            setDecryptedVideoUrl(URL.createObjectURL(combinedBlob));
        } catch (error) {
            setErrorMessage("Failed to decrypt the video: " + error.message);
        } finally {
            setLoading(false);
        }
    };

    const handleCloseVideo = () => {
        setSelectedVideo(null);
        setDecryptedVideoUrl(null);
    };

    const handleDeleteVideo = async () => {
        if (!selectedVideo) return;

        setLoading(true);
        setErrorMessage(null);

        try {
            const response = await pinnedFetch(`/api/video/${selectedVideo.name}`, {
                method: "DELETE",
            });

            if (response.ok) {
                setVideos(videos.filter(video => video.name !== selectedVideo.name));
                handleCloseVideo();
            } else {
                throw new Error('Failed to delete the video.');
            }
        } catch (error) {
            setErrorMessage(error.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Your Videos" width={520}>
                    {loading && <p>Loading videos…</p>}
                    {errorMessage && <p>Error: {errorMessage}</p>}
                    {!loading && videos.length === 0 && <p>No videos found.</p>}
                    {!loading && videos.length > 0 && (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 8 }}>
                            {videos.map(v => (
                                <div key={v.name} className="sunken-panel" style={{ padding: 4 }}>
                                    <p>{formatDate(v.name)}</p>
                                    <p>Shared by: {v.owner_username || "You"}</p>
                                    <button onClick={() => handleVideoSelect(v)}>View</button>
                                </div>
                            ))}
                        </div>
                    )}
                </Window98>

                {selectedVideo && decryptedVideoUrl && (
                    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                        <Window98 title={formatDate(selectedVideo.name)} width={480}>
                            <video src={decryptedVideoUrl} controls preload="auto" style={{ width: "100%" }} />
                            <div className="field-row" style={{ justifyContent: "space-between", marginTop: 6 }}>
                                <a href={decryptedVideoUrl} download={selectedVideo.name}>Download</a>
                                {!isTrustedUser && <button onClick={handleDeleteVideo} disabled={loading}>Delete</button>}
                                <button onClick={handleCloseVideo}>Close</button>
                            </div>
                        </Window98>
                    </div>
                )}
            </main>
        </>
    );
}
