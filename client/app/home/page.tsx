"use client";

import React, {useEffect, useRef, useState,} from "react";
import {useRouter} from "next/navigation";

import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";

import {logout} from "@/actions/auth";
import {encryptDatachunk, importKey,} from "@/cryptography/symmetric";
import {base64ToArrayBuffer} from "@/cryptography/asymmetric";
import {pinnedFetch} from "@/cryptography/certificate";
import {getSessionKeys} from "@/utils/session-util";


export default function HomePage() {
    const [name, setName] = useState("");
    const videoRef = useRef<HTMLVideoElement | null>(null);
    const mediaRecorderRef = useRef<MediaRecorder | null>(null);
    const userStreamRef = useRef<MediaStream | null>(null);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [mediaUrl, setMediaUrl] = useState<string | null>(null);
    const [recording, setRecording] = useState(false);
    const [videoId] = useState(`${Date.now()}`);
    const router = useRouter();

    useEffect(() => {
        (async () => {
            try {
                const token = localStorage.getItem("token");
                if (!token) return router.replace("/");

                const res = await pinnedFetch("/api/user/current", {
                    headers: {Authorization: `Bearer ${token}`},
                });
                if (!res.ok) return router.replace("/");

                const user = await res.json();
                if (user.trusted) {
                    return router.replace("/hometrusted");
                }

                setName(user.username);

                await initializeMedia(token, user.username);
            } catch (err) {
                console.error("Auth check or profile setup failed:", err);
                setErrorMessage("Session error. Please log in again.");
                await handleLogout();
            }
        })();

        return () => cleanupResources();
    }, []);

    const cleanupResources = () => {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state !== "inactive") {
            mediaRecorderRef.current.stop();
        }
        userStreamRef.current?.getTracks().forEach((t) => t.stop());
        userStreamRef.current = null;
        setRecording(false);
    };

    async function initializeMedia(token: string, username: string) {
        try {
            if (!navigator.mediaDevices?.getUserMedia) {
                setErrorMessage("Media devices not supported.");
                return;
            }

            // Lowe qual: 640x480 @ 15FPS
            const constraints = {
                video: {
                    width: {ideal: 640},
                    height: {ideal: 480},
                    frameRate: {ideal: 15}
                },
                audio: false
            };
            const userStream = await navigator.mediaDevices.getUserMedia(constraints);
            userStreamRef.current = userStream;

            //hidden video element to play the raw stream
            const videoElement = document.createElement('video');
            videoElement.srcObject = userStream;
            videoElement.muted = true;
            await videoElement.play();

            // canvas grayscale
            const canvas = document.createElement('canvas');
            canvas.width = 640;
            canvas.height = 480;
            const ctx = canvas.getContext('2d');

            // Apply  grayscale
            let animationFrameId: number;
            const drawGrayscale = () => {
                if (videoElement.videoWidth > 0 && videoElement.videoHeight > 0) {
                    ctx.drawImage(videoElement, 0, 0, canvas.width, canvas.height);
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const data = imageData.data;
                    for (let i = 0; i < data.length; i += 4) {
                        const avg = (data[i] + data[i + 1] + data[i + 2]) / 3;
                        data[i] = avg;     // Red
                        data[i + 1] = avg; // Green
                        data[i + 2] = avg; // Blue
                    }
                    ctx.putImageData(imageData, 0, 0);
                }
                animationFrameId = requestAnimationFrame(drawGrayscale);
            };
            drawGrayscale();

            const grayscaleStream = canvas.captureStream(15);

            if (videoRef.current) {
                videoRef.current.srcObject = grayscaleStream;
            }

            // VP8 efficient
            let mimeType = 'video/webm;codecs=vp8';
            if (!MediaRecorder.isTypeSupported(mimeType)) {
                mimeType = 'video/webm';
            }

            const {symmBase64} = getSessionKeys();
            if (!symmBase64) {
                throw new Error("Session keys not available. Log in again.");
            }
            const symKey = await importKey(base64ToArrayBuffer(symmBase64));

            const recorder = new MediaRecorder(grayscaleStream, {mimeType});
            mediaRecorderRef.current = recorder;

            const chunks: BlobPart[] = [];
            recorder.ondataavailable = async (ev) => {
                if (ev.data.size > 0) {
                    chunks.push(ev.data);

                    // encrypt/post chunks
                    const encryptedChunk = await encryptDatachunk(ev.data, symKey);
                    const payload = new FormData();
                    payload.append("encryptedChunk", JSON.stringify(encryptedChunk));
                    payload.append(
                        "metadata",
                        JSON.stringify({
                            videoId,
                            chunkIndex: chunks.length,
                            timestamp: Date.now(),
                            chunkSize: ev.data.size,
                        })
                    );
                    await pinnedFetch("/stream", {
                        method: "POST",
                        body: payload,
                        headers: {Authorization: `Bearer ${token}`},
                    });
                }
            };
            recorder.onstop = () => {
                cancelAnimationFrame(animationFrameId);
                videoElement.pause();
                const blob = new Blob(chunks, {type: mimeType});
                setMediaUrl(URL.createObjectURL(blob));
                setRecording(false);
            };

            setRecording(true);
            recorder.start(800);
            setErrorMessage(null);
        } catch (err: any) {
            console.error("Media init failed:", err);
            setErrorMessage(err?.message ?? "Could not start camera.");
        }
    }

    const handleLogout = async () => {
        cleanupResources();
        await logout();
        router.replace("/");
    };

    useEffect(() => {
        const handleVisibilityChange = async () => {
            if (document.visibilityState === 'hidden') {
                cleanupResources();
            } else {
                const token = localStorage.getItem("token");
                if (token && name) {
                    await initializeMedia(token, name);
                }
            }
        };

        document.addEventListener('visibilitychange', handleVisibilityChange);

        return () => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
        };
    }, [name]);

    return (
        <>
            <Navbar98/>
            <main
                style={{display: "flex", justifyContent: "center", marginTop: 40}}
            >
                <Window98 title="Secure Software Design" width={440}>
                    <fieldset style={{padding: 4}}>
                        <legend>Recording</legend>
                        {errorMessage ? (
                            <p>{errorMessage}</p>
                        ) : (
                            <>
                                <video
                                    ref={videoRef}
                                    autoPlay
                                    muted
                                    playsInline
                                    style={{width: "100%", maxHeight: 480}}
                                />
                                {recording && <p style={{marginTop: 4}}>◉ LIVE</p>}
                            </>
                        )}
                    </fieldset>
                </Window98>
            </main>
        </>
    );
}
