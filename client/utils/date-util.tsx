export const formatDate = (input: string): string => {
    if (!input) return "Invalid Date";
    const numMatch = input.match(/^(\d{13})/);
    if (numMatch) {
        const d = new Date(Number(numMatch[1]));
        if (!isNaN(d.getTime())) return asNice(d);
    }

    const dashMatch = input.match(
        /(\d{4})-(\d{2})-(\d{2})[-_](\d{2})[-_](\d{2})/
    );
    if (dashMatch) {
        const [_, y, m, d, h, min] = dashMatch.map(Number);
        const date = new Date(y, m - 1, d, h, min);
        if (!isNaN(date.getTime())) return asNice(date);
    }

    const tryDate = new Date(input.replace(/\.[^.]+$/, ""));
    if (!isNaN(tryDate.getTime())) return asNice(tryDate);

    return "Invalid Date";
};

function asNice(date: Date): string {
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(date.getDate())}/${pad(date.getMonth() + 1)}/${date.getFullYear()} at ${pad(
        date.getHours()
    )}h${pad(date.getMinutes())}`;
}
