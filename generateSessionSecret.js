const crypto = require('crypto');

function generateSessionSecret() {
    return crypto.randomBytes(32).toString('hex');
}

const sessionSecret = generateSessionSecret();
console.log('Generated SESSION_SECRET:', sessionSecret);
