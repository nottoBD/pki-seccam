"use client";

import React, {useEffect, useRef, useState,} from "react";
import {useRouter} from "next/navigation";

import Navbar98 from "@/components/Navbar98";
import Window98 from "@/components/Window98";

import {handleProfile, handleProfileTrusted} from "@/cryptography/handlers";
import {logout} from "@/actions/auth";
import {encryptDatachunk, importKey,} from "@/cryptography/symmetric";
import {base64ToArrayBuffer, decryptWithPrivateKey} from "@/cryptography/asymmetric";
import {pinnedFetch} from "@/cryptography/certificate";
import {getKey} from "@/keys/indexed-keys";
import {getSessionKeys, setSessionKeys} from "@/keys/session-keys";


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
                const resData = await res.json();

                let displayName = "";
                if (resData.isTrustedUser) {
                    const p = await handleProfileTrusted(resData);
                    displayName = p.fullname;
                    setName(displayName);
                    return router.replace("/hometrusted");
                } else {
                    const p = await handleProfile(resData);
                    displayName = p.username;
                    setName(displayName);
                }

                //multidevice card if primary
                try {
                    const devRes = await pinnedFetch("/api/device/list", {
                        headers: {Authorization: `Bearer ${token}`},
                    });

                    if (devRes.ok) {
                        const devData = await devRes.json();
                        const primary = devData.find((d: any) => d.isPrimary);
                        const localId = localStorage.getItem("device_id");
                        if (primary && localId && primary.deviceId === localId) {
                            //TODO: add primary device logic
                        }
                    }
                } catch (err) {
                    console.error("Could not fetch device list:", err);
                }

                // camera after auth OK
                await initializeMedia(token, resData.isTrustedUser, resData.username);
            } catch (err) {
                console.error("Auth check failed:", err);
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
    };

    async function initializeMedia(token: string, trusted: boolean, username: string) {
        try {
            if (!navigator.mediaDevices?.getUserMedia) {
                setErrorMessage("Media devices not supported.");
                return;
            }
            const userStream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true,
            });
            userStreamRef.current = userStream;
            if (videoRef.current) videoRef.current.srcObject = userStream;

            let mimeType: string =
                'video/webm;codecs="vp8, opus"' as const;
            if (!MediaRecorder.isTypeSupported(mimeType))
                mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp9')
                    ? 'video/webm;codecs=vp9'
                    : MediaRecorder.isTypeSupported('video/webm;codecs=vp8')
                        ? 'video/webm;codecs=vp8'
                        : "video/webm";


            let {symmBase64} = getSessionKeys();
            let symKeyBase64 = symmBase64;

            if (!symKeyBase64) {
                const resp = await pinnedFetch("/getSymmetric", {
                    headers: {Authorization: `Bearer ${token}`},
                });
                const {encryptedSymmetricKey} = await resp.json();

                const deviceId = localStorage.getItem("device_id")!;
                const privKey = await getKey(deviceId);
                if (!privKey) throw new Error("Device private key not found");

                symKeyBase64 = await decryptWithPrivateKey(encryptedSymmetricKey, privKey);
                setSessionKeys(symKeyBase64, getSessionKeys().hmacBase64 ?? '');
            }
            const symKey = await importKey(base64ToArrayBuffer(symKeyBase64));

            const recorder = new MediaRecorder(userStream, {mimeType});
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
                const blob = new Blob(chunks, {type: mimeType});
                setMediaUrl(URL.createObjectURL(blob));
                setRecording(false);
            };

            setRecording(true);
            recorder.start(500);
            setErrorMessage(null);
        } catch (err: any) {
            console.error("Media init failed:", err);
            setErrorMessage(
                err?.message ??
                "Could not start camera. Check permissions or another app may be using it."
            );
        }
    }

    const handleLogout = async () => {
        cleanupResources();
        await logout();
        router.replace("/");
    };


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
