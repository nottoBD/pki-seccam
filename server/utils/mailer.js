const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'mailpit',
    port: parseInt(process.env.SMTP_PORT || '1025', 10),
    secure: false,
    requireTLS: true,
    tls: {
        minVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        servername: 'mailpit'
    }
});

exports.sendVerificationMail = (to, username, token) => {
    const link = `${process.env.NEXT_PUBLIC_API_ORIGIN}/verify-email?` +
        `token=${token}&username=${encodeURIComponent(username)}`;

    return transporter.sendMail({
        from: '"SEC CAM" <noreply@seccam.local>',
        to,
        subject: 'Verify your SEC CAM e-mail',
        text: `Hi ${username},\n\nPlease verify your e-mail by visiting:\n${link}\n\n` +
            'The link is valid for 24 h.',
        html: `<p>Hi <b>${username}</b>,</p><p>Please verify your e-mail:</p>` +
            `<p><a href="${link}">${link}</a></p><p>This link expires in 24 h.</p>`
    });
};
