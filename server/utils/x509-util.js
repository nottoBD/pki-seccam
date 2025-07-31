const crypto = require('crypto');


/**
 * @param {string} pemBundle  One PEM cert or a full chain.
 * @returns {string}          Hex serial or '' on failure.
 */
function getSerialNumber(pemBundle = '') {
    try {
        // Grab bundled leaf
        const [leaf] = pemBundle.match(
            /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/
        ) || [];

        if (!leaf) return '';

        const x509 = new crypto.X509Certificate(leaf);
        return x509.serialNumber.toUpperCase();
    } catch {
        return '';
    }
}

module.exports = {getSerialNumber};
