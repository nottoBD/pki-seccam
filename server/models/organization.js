const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
    name: {type: String, required: true},
    country: {type: String, required: true},

    certPath: {type: String, required: true},   // /certs/org_<name>.crt.pem
    serialNumber: {type: String, required: true},
    issuedAt: {type: Date, required: true},
});

organizationSchema.index(
    {name: 1, country: 1},
    {
        unique: true,
        collation: {locale: 'en', strength: 2} // case insensitiv
    }
);

module.exports = mongoose.model('Organization', organizationSchema);
