export const formatDate = (timestampString) => {
    const timestamp = parseInt(timestampString, 10);
    if (isNaN(timestamp)) return "Invalid Date";

    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return "Invalid Date";

    const day = String(date.getDate()).padStart(2, "0");
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");

    return `${day}/${month}/${year} at ${hours}h${minutes}`;
};
