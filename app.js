const crypto = require('crypto');
const axios = require('axios');

/**
 * Load access token from localStorage if available and valid to minize the
 * number of requests to the authentication server.
 * 
 * @param {context.store} store 
 * @param {context.request} req 
 * @returns true if access token was found in localStorage
 */
async function loadStoredAccessToken(store, req) {
    const access = await store.getItem('access');
    if (access) {
        const accessData = JSON.parse(access);
        const now = new Date().getTime();
        if (now < accessData.expires_in * 1000) {
            req.setHeader('Authorization', `Bearer ${accessData.access_token}`);
            return true;
        }
        else {
            console.log('Access token expired - reauthenticating');
            await store.removeItem('access');
        }
    }

    return false;
}

/**
 * @returns 32 random bytes encoded using URL-safe Base64.
 */
function getRandomBytes() {
    const data = new Uint32Array(32);
    self.crypto.getRandomValues(data);

    return Buffer.from(data).toString('base64url'); 
}

/**
 * Generate the JWT used to retrieve the access token from the authentication server.
 * 
 * @param {string} subject JWT subject
 * @param {string} audience JWT audience
 * @param {string} certificateBase64 Base64 encoded certificate, without header/footer
 * @param {string} privateKeyBase64 Private key in PEM format, including the header/footer
 * @returns The JWT
 */
function generateJWT(subject, audience, certificateBase64, privateKeyBase64) {
    const header = {
        "alg" : "RS256",
        "typ" : "JWT",
        "x5c" : [ certificateBase64 ]
    };

    const now = new Date().getTime() / 1000;

    const randomBase64 = getRandomBytes();

    const payload = {
        "sub" : subject,
        "aud" : audience,
        "exp" : now + 3600,
        "iat" : now,
        "jti" : randomBase64
    };

    const headerBase64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');

    const signaturePayload = headerBase64 + "." + payloadBase64;      
    const signerObject = crypto.createSign("RSA-SHA256");
    signerObject.update(signaturePayload);

    const signature = signerObject.sign(privateKeyBase64, "base64url");
    
    return signaturePayload + "." + signature;
}

module.exports.requestHooks = [
    async (context) => {
        const req = context.request;
        const store = context.store;

        const audience = req.getEnvironmentVariable('auth-jws-audience');
        const subject = req.getEnvironmentVariable('auth-jws-subject');
        const accessTokenURL = req.getEnvironmentVariable('auth-jws-access-token-url');
        const privateKeyBase64 = req.getEnvironmentVariable('auth-jws-private-key');
        const certificateBase64 = req.getEnvironmentVariable('auth-jws-certificate');

        if (!audience || !subject || !accessTokenURL || !privateKeyBase64 || !certificateBase64) {
            console.log('auth-jws is not configured');
            return;
        }

        try {
            if (await loadStoredAccessToken(store, req)) {
                return;
            }

            const jwt = generateJWT(subject, audience, certificateBase64, privateKeyBase64);

            const res = await axios.post(accessTokenURL, 'grant_type=client_credentials', {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': `Bearer ${jwt}`
                }}).then(res => res.data) ;

            store.setItem('access', JSON.stringify(res));
            req.setHeader('Authorization', `Bearer ${res.access_token}`);
        }
        catch (e) {
            console.error(e);
            // Clear storage to start from the begining, if an error has occured
            await store.removeItem('access');
        }
    }
];