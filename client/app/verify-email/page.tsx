'use client';

export const dynamic = 'force-dynamic';

import {Suspense, useEffect, useState} from 'react';
import {useSearchParams} from 'next/navigation';
import Navbar98 from '@/components/Navbar98';
import Window98 from '@/components/Window98';
import {pinnedFetch} from '@/cryptography/certificate';

export default function VerifyEmail() {
    const params = useSearchParams();
    const [msg, setMsg] = useState('Verifying…');
    const [closedMsgVisible, setClosedMsgVisible] = useState(false);

    useEffect(() => {
        const token = params.get('token');
        const username = params.get('username');
        if (!token || !username) {
            setMsg('Bad link');
            return;
        }

        (async () => {
            try {
                await pinnedFetch(
                    '/api/user/verify?' +
                    new URLSearchParams({token, username})
                );
                setMsg('✅ E‑mail verified – you can now log in.');
            } catch (e: any) {
                setMsg(e.response?.data?.message || 'Verification failed');
            }
        })();
    }, [params]);

    const handleClose = () => {
        window.close();
        setClosedMsgVisible(true);
    };

    return (
        <>
            <Navbar98/>
            <main style={{display: 'flex', justifyContent: 'center', marginTop: 60}}>
                <Suspense fallback={<Window98 title="E‑mail Verification" width={320}><p>Loading…</p></Window98>}>
                    <Window98 title="E‑mail Verification" width={320}>
                        <p>{msg}</p>

                        {msg.startsWith('✅') && !closedMsgVisible && (
                            <p>
                                <button onClick={handleClose}>
                                    OK
                                </button>
                            </p>
                        )}

                        {closedMsgVisible && (
                            <p>You can safely login now.</p>
                        )}
                    </Window98>
                </Suspense>
            </main>
        </>
    );
}
