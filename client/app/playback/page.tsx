"use client";
import React, {useEffect, useRef, useState} from "react";
import {useRouter} from "next/navigation";
import {decryptDataChunk, importKey} from '@/cryptography/symmetric';
import {base64ToArrayBuffer, decryptWithPrivateKey, importPrivateKey} from '@/cryptography/asymmetric';
import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";
import {formatDate} from "@/utils/date-util";
import {pinnedFetch} from "@/cryptography/certificate";
import {getSessionKeys} from "@/utils/session-util";


export default function PlaybackPage() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isTrustedUser, setIsTrustedUser] = useState(false);
    const [isCheckingAuth, setIsCheckingAuth] = useState(true);
    const [trustedUserVideos, setTrustedUserVideos] = useState([]);
    const [name, setName] = useState("");
    const [videos, setVideos] = useState([]);
    const [selectedVideo, setSelectedVideo] = useState(null);
    const [decryptedVideoUrl, setDecryptedVideoUrl] = useState(null);
    const [errorMessage, setErrorMessage] = useState(null);
    const [loading, setLoading] = useState(false);
    const router = useRouter();
    const [alert, setAlert] = useState<{ type: "success" | "error"; message: string } | null>(null);
    const videoPlayerRef = useRef<HTMLVideoElement | null>(null);

    useEffect(() => {
        if (alert) {
            const timer = setTimeout(() => setAlert(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [alert]);

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
                    setIsTrustedUser(data.isTrustedUser);
                    setName(data.username);
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

    const fetchUserVideos = async () => {
        setLoading(true);
        setErrorMessage(null);

        try {
            const token = localStorage.getItem("token");
            let response;
            if (!isTrustedUser) {
                response = await pinnedFetch("/api/video/list", {
                    headers: {Authorization: `Bearer ${token}`},
                });
            } else {
                response = await pinnedFetch("/api/video/trustedList", {
                    headers: {Authorization: `Bearer ${token}`},
                });
            }

            if (response.ok) {
                const responseData = await response.json();
                if (!isTrustedUser) {
                    setVideos(responseData.videos);
                } else {
                    setTrustedUserVideos(responseData);
                    const list_videos = responseData.flatMap((item: any) => item.videos);
                    setVideos(list_videos);
                }
            } else {
                setVideos([]);
            }
        } catch (error) {
            console.error("Error fetching videos:", error);
            setErrorMessage("An error occurred while fetching your videos.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (isAuthenticated) {
            fetchUserVideos();
        }
    }, [isAuthenticated]);

    const handleVideoSelect = async (video: any) => {
        setSelectedVideo(video);
        setDecryptedVideoUrl(null);
        setLoading(true);
        setErrorMessage(null);

        try {
            const token = localStorage.getItem("token");
            let encryptedSymmetricKey;
            let privateKey;
            let owner_username;
            let symmetricKey;
            if (!isTrustedUser) {
                owner_username = name; // /current endpoint
                const {symmBase64} = getSessionKeys();
                if (!symmBase64) {
                    throw new Error("Symmetric key not found in session");
                }
                symmetricKey = await importKey(base64ToArrayBuffer(symmBase64));
            } else {
                for (const item of trustedUserVideos) {
                    if (item.videos.some((v: any) => v.name === video.name)) {
                        encryptedSymmetricKey = item.encrypted_symmetric_key;
                        owner_username = item.username;
                        break;
                    }
                }
                privateKey = localStorage.getItem('org_identity_priv');
                if (!privateKey) {
                    throw new Error("Private key not found for the user.");
                }

                const importedPrivateKey =
                    typeof privateKey === "string"
                        ? await importPrivateKey(privateKey, "decrypt")
                        : privateKey;

                const symmetricKeyBase64 =
                    await decryptWithPrivateKey(encryptedSymmetricKey, importedPrivateKey);

                symmetricKey =
                    await importKey(base64ToArrayBuffer(symmetricKeyBase64));
            }

            let chunkResponse;
            let chunkData;
            if (!isTrustedUser) {
                chunkResponse = await pinnedFetch(`/api/video/${video.name}/${owner_username}/chunks`, {
                    headers: {Authorization: `Bearer ${token}`},
                });
                chunkData = await chunkResponse.json();
            } else {
                chunkResponse = await pinnedFetch(`/api/video/${video.name}/${owner_username}/chunks`, {
                    headers: {Authorization: `Bearer ${token}`},
                });
                chunkData = await chunkResponse.json();
            }

            if (!chunkResponse.ok || !chunkData || chunkData.length === 0) {
                throw new Error("No chunks found for this video.");
            }

            const encryptedChunks = chunkData;

            const decryptedChunks = await Promise.all(
                encryptedChunks.map((chunk: any) => decryptDataChunk(chunk.chunk, symmetricKey))
            );

            const combinedBlob = new Blob(decryptedChunks, {type: "video/webm"});

            const videoUrl = URL.createObjectURL(combinedBlob);
            setDecryptedVideoUrl(videoUrl);
        } catch (error) {
            console.error("Error decrypting video:", error);
            setErrorMessage("Failed to decrypt the video.");
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteVideo = async () => {
        try {
            const response = await pinnedFetch(`/api/video/${selectedVideo.name}`, {
                method: 'DELETE',
                headers: {Authorization: `Bearer ${localStorage.getItem("token")}`},
            });

            if (response.ok) {
                setAlert({type: "success", message: "Video deleted successfully!"});

                setVideos((prevVideos) => prevVideos.filter((video) => video.name !== selectedVideo.name)
                );

                setSelectedVideo(null);
            } else if (response.status === 401) {
                setAlert({type: "error", message: "You cannot delete the video."});
            }
        } catch (error) {
            console.error("Error deleting video:", error);
            setAlert({type: "error", message: "An error occurred while deleting the video."});
        }
    };

    const handleCloseVideo = () => {
        setSelectedVideo(null);
        setDecryptedVideoUrl(null);
    };

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Your Videos" width={520}>
                    {loading && <p>Loading videos…</p>}
                    {!loading && videos.length === 0 && <p>No videos found.</p>}
                    {!loading && videos.length > 0 && (
                        <div
                            style={{
                                display: "grid",
                                gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))",
                                gap: 8,
                                marginTop: 8,
                            }}
                        >
                            {videos.map((v, idx) => (
                                <div key={idx} className="sunken-panel" style={{padding: 4, textAlign: "center"}}>
                                    <p style={{fontSize: 12, marginBottom: 4}}>{formatDate(v.name)}</p>
                                    <p style={{fontSize: 11, marginBottom: 6}}>
                                        Shared by: {v.sharedBy ?? "You"}
                                    </p>
                                    <button onClick={() => handleVideoSelect(v)}>View</button>
                                </div>
                            ))}

                        </div>
                    )}
                </Window98>
                {selectedVideo && (
                    <div
                        style={{
                            position: "fixed",
                            inset: 0,
                            background: "rgba(0,0,0,0.4)",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            zIndex: 1000,
                        }}
                    >
                        <Window98 title={formatDate(selectedVideo.name)} width={480}>
                            {loading && <p>Loading video chunks...</p>}
                            <video
                                ref={videoPlayerRef}
                                src={decryptedVideoUrl}
                                controls
                                preload="auto"  // Encourage buffering
                                style={{width: "100%", height: "auto"}}
                            />
                            <div
                                className="field-row"
                                style={{justifyContent: "space-between", marginTop: 6}}
                            >
                                {decryptedVideoUrl && (
                                    <a
                                        href={decryptedVideoUrl}
                                        download={selectedVideo.name}
                                        className="default"
                                    >
                                        Download
                                    </a>
                                )}
                                {!isTrustedUser && (
                                    <button onClick={handleDeleteVideo}>Delete</button>
                                )}
                                <button onClick={handleCloseVideo}>Close</button>
                            </div>
                        </Window98>
                    </div>
                )}
            </main>
        </>
    );
}