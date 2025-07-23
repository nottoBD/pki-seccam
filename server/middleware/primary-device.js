const User = require('../models/user');
const TrustedUser = require('../models/trusteduser');


module.exports = async (req, res, next) => {
    const account = (await User.findOne({username: req.user.username}))
        || (await TrustedUser.findOne({username: req.user.username}));

    const primary = account.devices.find((d) => d.status === 'primary');
    if (!primary) return res.status(423).json({message: 'No primary device registered.'});

    if (req.user.deviceId !== primary.deviceId)
        return res.status(403).json({message: 'Only primary device can perform this action.'});

    next();
};
