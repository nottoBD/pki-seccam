"use client";
import React, {useCallback, useEffect, useState} from "react";
import {useRouter} from "next/navigation";
import {io} from "socket.io-client";

import Window98 from "@/components/Window98";
import Navbar98 from "@/components/Navbar98";

import {formatDate} from "@/utils/date-util";
import {handleProfile, handleProfileTrusted, shareKeysWithDevice,} from "@/cryptography/handlers";
import {pinnedFetch} from "@/cryptography/certificate";

interface Dev {
    deviceId: string;
    name: string;
    status: "primary" | "active" | "pending" | "revoked";
    issuedAt: string | Date;
    isPrimary?: boolean; // cfr GET /device/list
}

interface ApprovedEvt {
    deviceId: string;
    certificate: string; // PEM
}

// only newest pending request/deviceId
const dedupPending = (list: Dev[]) => {
    const map = new Map<string, Dev>();
    list
        .filter((d) => d.status === "pending")
        .forEach((d) => {
            const prev = map.get(d.deviceId);
            if (
                !prev ||
                new Date(d.issuedAt).getTime() > new Date(prev.issuedAt).getTime()
            ) {
                map.set(d.deviceId, d);
            }
        });
    return Array.from(map.values());
};

export default function MultiDeviceAccess() {
    const router = useRouter();

    const [displayName, setDisplayName] = useState("");
    const [pending, setPending] = useState<Dev[]>([]);
    const [alert, setAlert] = useState<
        null | { type: "success" | "error"; message: string }
    >(null);

    useEffect(() => {
        (async () => {
            try {
                /* current user */
                const curRes = await pinnedFetch(
                    "/api/user/current",
                    {headers: {Authorization: `Bearer ${localStorage.getItem("token")}`}}
                );

                const curData = await curRes.json();

                const name = curData.data.isTrustedUser
                    ? (await handleProfileTrusted(curData.data)).fullname
                    : (await handleProfile(curData.data)).username;
                setDisplayName(name);

                const listRes = await pinnedFetch(
                    "/api/device/list",
                    {headers: {Authorization: `Bearer ${localStorage.getItem("token")}`}}
                );

                const listData = await listRes.json();

                const localDevId = localStorage.getItem("device_id");
                const primary = listData.find((d: Dev) => d.isPrimary);
                if (!primary || primary.deviceId !== localDevId) {
                    return router.push(curData.isTrustedUser ? "/hometrusted" : "/home");
                }
                setPending(dedupPending(listData));
            } catch (err) {
                console.error(err);
                router.push("/");
            }
        })();
    }, []);

    const refresh = useCallback(async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) return;
            const res = await pinnedFetch(
                "/api/device/list",
                {headers: {Authorization: `Bearer ${token}`}}
            );

            const data = await res.json();
            setPending(dedupPending(data));
        } catch {
        }
    }, []);

    useEffect(() => {
        const socket = io("", {transports: ["websocket"]});

        socket.on("device‑pending", refresh);
        socket.on("device‑denied", refresh);
        socket.on("device‑approved", async (data: ApprovedEvt) => {
            try {
                await shareKeysWithDevice(data.deviceId, data.certificate);
            } catch (e) {
                console.error("shareKeysWithDevice failed:", e);
            }
            await refresh();
        });

        return () => {
            socket.disconnect();
        };
    }, [refresh]);


    const act = async (deviceId: string, action: "approve" | "deny") => {
        try {
            const token = localStorage.getItem("token");
            const res = await pinnedFetch(`/api/device/${deviceId}/${action}`, {
                method: 'POST',
                headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
            });
            const resData = await res.json();

            if (action === "approve") {
                await shareKeysWithDevice(deviceId, resData.certificate);
            }
            await refresh();
            setAlert({
                type: "success",
                message: `Device ${action === "approve" ? "approved" : "denied"}.`,
            });
        } catch (err: any) {
            setAlert({
                type: "error",
                message: err.response?.data?.message || "Server error",
            });
        }
    };

    return (
        <>
            <Navbar98/>
            <main style={{display: "flex", justifyContent: "center", marginTop: 40}}>
                <Window98 title="Multi Device Access" width={440}>
                    <h3 style={{marginTop: 8, marginBottom: 4}}>Pending Devices</h3>
                    {alert && (
                        <p>
                            {alert.type === "error" ? "Error" : "Success"}: {alert.message}
                        </p>
                    )}
                    {pending.length === 0 ? (
                        <p>No pending device requests.</p>
                    ) : (
                        <ul style={{marginBottom: 12}}>
                            {pending.map((dev) => (
                                <li
                                    key={`${dev.deviceId}_${new Date(dev.issuedAt).getTime()}`}
                                    style={{display: "flex", justifyContent: "space-between"}}
                                >
                                    <div>
                                        <b>{dev.name}</b> <br/>
                                        Requested on {formatDate(String(dev.issuedAt))}
                                    </div>

                                    <div style={{display: "flex", gap: 4}}>
                                        <button onClick={() => act(dev.deviceId, "approve")}>
                                            Approve
                                        </button>
                                        <button onClick={() => act(dev.deviceId, "deny")}>
                                            Deny
                                        </button>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    )}
                </Window98>
            </main>
        </>
    );
}
