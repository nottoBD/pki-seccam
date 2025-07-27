import type {Metadata} from "next";
import React from "react";
import "98.css";

export const metadata: Metadata = {
    title: "PKI-based Security System",
};

export default function RootLayout({children}: { children: React.ReactNode }) {
    return (
        <html lang="en" suppressHydrationWarning>
        <body style={{margin: 0, background: "#008080"}}>
        {children}
        </body>
        </html>
    );
}
