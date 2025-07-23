import React from "react";

export default function Window98({
                                     title,
                                     children,
                                     width = 400,
                                 }: {
    title: string;
    children?: React.ReactNode;
    width?: number | string;
}) {
    return (
        <div className="window" style={{width}}>
            <div className="title-bar">
                <div className="title-bar-text">{title}</div>
                <div className="title-bar-controls">
                    <button aria-label="Minimize"></button>
                    <button aria-label="Maximize"></button>
                    <button aria-label="Close"></button>
                </div>
            </div>
            <div className="window-body">{children}</div>
        </div>
    );
}
