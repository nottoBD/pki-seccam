let cryptoPackage = null;

export const setCryptoPackage = (pkg) => { cryptoPackage = pkg; };
export const getCryptoPackage = () => cryptoPackage;
export const clearCryptoPackage = () => { cryptoPackage = null; };
