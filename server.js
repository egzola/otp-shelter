import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(
    fileURLToPath(import.meta.url)
);

const app = express();

const PORT =
    process.env.PORT || 3010;


/*
|--------------------------------------------------------------------------
| Directories
|--------------------------------------------------------------------------
*/

const DATA_DIR =
    path.join(__dirname, "data");

const VAULT_FILE =
    path.join(DATA_DIR, "vault.json");


fs.mkdirSync(
    DATA_DIR,
    {
        recursive: true,
        mode: 0o700
    }
);


/*
|--------------------------------------------------------------------------
| Security configuration
|--------------------------------------------------------------------------
*/

const SESSION_COOKIE =
    "otp_shelter_session";

const SESSION_TIMEOUT =
    1000 * 60 * 15; // 15 minutes

const MAX_SESSIONS =
    20;


/*
|--------------------------------------------------------------------------
| Express
|--------------------------------------------------------------------------
*/

/*
 * Security headers. CSP is disabled here because the current UI uses inline
 * scripts/styles; the remaining Helmet protections stay enabled.
 */
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(
    express.json({
        limit: "5mb"
    })
);


/*
|--------------------------------------------------------------------------
| Security headers
|--------------------------------------------------------------------------
*/

app.use(
    (req, res, next) => {

        res.setHeader(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private"
        );

        res.setHeader(
            "Pragma",
            "no-cache"
        );

        res.setHeader(
            "Expires",
            "0"
        );

        res.setHeader(
            "X-Content-Type-Options",
            "nosniff"
        );

        res.setHeader(
            "Referrer-Policy",
            "no-referrer"
        );

        next();
    }
);


app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);


/*
|--------------------------------------------------------------------------
| Sessions
|--------------------------------------------------------------------------
|
| Password is NEVER stored.
|
| Only the derived encryption key exists temporarily
| in memory while the session is active.
|
*/

const sessions =
    new Map();


function parseCookies(req) {

    const cookie =
        req.headers.cookie;

    if (!cookie) {
        return {};
    }

    return Object.fromEntries(
        cookie
            .split(";")
            .map(
                item => {

                    const index =
                        item.indexOf("=");

                    if (index < 0) {
                        return null;
                    }

                    return [
                        item
                            .slice(0, index)
                            .trim(),

                        decodeURIComponent(
                            item
                                .slice(index + 1)
                                .trim()
                        )
                    ];
                }
            )
            .filter(Boolean)
    );
}


function createSession(key, backupKey = null) {

    /*
     * Prevent unlimited memory usage.
     */

    if (
        sessions.size >=
        MAX_SESSIONS
    ) {

        const oldest =
            sessions
                .entries()
                .next()
                .value;

        if (oldest) {

            const [
                sessionId,
                session
            ] = oldest;

            destroySession(
                sessionId,
                session
            );
        }
    }

    const sessionId =
        crypto
            .randomBytes(32)
            .toString("hex");

    sessions.set(
        sessionId,
        {
            key,
            backupKey,
            createdAt: Date.now(),
            lastUsed: Date.now()
        }
    );

    return sessionId;
}


function destroySession(
    sessionId,
    session = null
) {

    const current =
        session ||
        sessions.get(sessionId);

    if (
        current &&
        current.key
    ) {

        try { current.key.fill(0); } catch { }
        try { current.backupKey?.fill(0); } catch { }
    }

    sessions.delete(
        sessionId
    );
}


function invalidateOtherSessions(currentSessionId) {
    for (const [id, session] of sessions) {
        if (id !== currentSessionId) {
            destroySession(id, session);
        }
    }
}

function getSession(req) {

    const cookies =
        parseCookies(req);

    const sessionId =
        cookies[
        SESSION_COOKIE
        ];

    if (!sessionId) {
        return null;
    }

    const session =
        sessions.get(sessionId);

    if (!session) {
        return null;
    }

    const now =
        Date.now();

    if (
        now -
        session.lastUsed >
        SESSION_TIMEOUT
    ) {

        destroySession(
            sessionId,
            session
        );

        return null;
    }

    session.lastUsed =
        now;

    return {
        id: sessionId,
        ...session
    };
}


/*
|--------------------------------------------------------------------------
| Authentication middleware
|--------------------------------------------------------------------------
*/

function requireAuth(
    req,
    res,
    next
) {

    const session =
        getSession(req);

    if (!session) {

        return res
            .status(401)
            .json({
                error:
                    "Vault is locked."
            });
    }

    req.session =
        session;

    next();
}


/*
|--------------------------------------------------------------------------
| Vault structure
|--------------------------------------------------------------------------
*/

function createEmptyVault() {

    return {
        version: 2,

        createdAt:
            new Date()
                .toISOString(),

        sites: []
    };
}


function validateVault(vault) {

    if (
        !vault ||
        typeof vault !== "object"
    ) {
        throw new Error(
            "Invalid vault."
        );
    }

    if (
        !Array.isArray(
            vault.sites
        )
    ) {
        throw new Error(
            "Invalid vault structure."
        );
    }

    if (
        vault.sites.length >
        10000
    ) {
        throw new Error(
            "Vault contains too many accounts."
        );
    }

    return true;
}


/*
|--------------------------------------------------------------------------
| Password validation
|--------------------------------------------------------------------------
*/

function validatePassword(password) {

    if (
        typeof password !==
        "string"
    ) {
        throw new Error(
            "Password is required."
        );
    }

    /*
     * Avoid silently accepting an accidental
     * empty password.
     */

    if (
        password.length < 9
    ) {
        throw new Error(
            "Password must contain at least 9 characters."
        );
    }

    /*
     * Prevent abuse through extremely large input.
     */

    if (
        password.length > 1024
    ) {
        throw new Error(
            "Password is too long."
        );
    }

    return password;
}


/*
|--------------------------------------------------------------------------
| Key derivation
|--------------------------------------------------------------------------
|
| Password is NEVER stored.
|
| salt is random and stored inside vault.json.
|
*/

function deriveKey(
    password,
    salt,
    kdf = {}
) {

    validatePassword(
        password
    );

    const N =
        kdf.N || 32768;

    const r =
        kdf.r || 8;

    const p =
        kdf.p || 1;

    const maxmem =
        128 *
        N *
        r *
        2;

    return crypto.scryptSync(
        password,
        salt,
        32,
        {
            N,
            r,
            p,
            maxmem
        }
    );
}


/*
|--------------------------------------------------------------------------
| Portable backup key
|--------------------------------------------------------------------------
|
| This key is derived from the master password with a fixed, application
| domain-separated salt. It exists only in the authenticated session.
| It allows encrypted backups to move between machines without asking for
| the password again after login.
|
*/

const BACKUP_SALT = Buffer.from("otp-shelter:portable-backup:v1", "utf8");

function deriveBackupKey(password) {
    return deriveKey(password, BACKUP_SALT, { N: 32768, r: 8, p: 1 });
}


/*
|--------------------------------------------------------------------------
| Vault encryption
|--------------------------------------------------------------------------
*/

function encryptVault(
    vault,
    key,
    existingKdf = null
) {

    validateVault(vault);

    /*
     * A new random IV must be generated
     * every time the vault is encrypted.
     */

    const iv =
        crypto.randomBytes(12);

    /*
     * Salt remains stable for the same vault.
     *
     * When creating a new vault:
     * generate a new random salt.
     */

    const salt =
        existingKdf?.salt
            ? Buffer.from(
                existingKdf.salt,
                "base64"
            )
            : crypto.randomBytes(16);

    const kdf = {
        name: "scrypt",

        salt:
            salt.toString(
                "base64"
            ),

        N:
            existingKdf?.N ||
            32768,

        r:
            existingKdf?.r ||
            8,

        p:
            existingKdf?.p ||
            1,

        dkLen: 32
    };


    /*
     * Authenticate metadata.
     */

    const aad =
        Buffer.from(
            JSON.stringify({
                format:
                    "otp-shelter",

                version: 2,

                kdf: {
                    name: kdf.name,
                    N: kdf.N,
                    r: kdf.r,
                    p: kdf.p,
                    dkLen: kdf.dkLen
                },

                cipher:
                    "aes-256-gcm"
            })
        );


    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    cipher.setAAD(
        aad
    );


    const plaintext =
        JSON.stringify(
            vault
        );


    const ciphertext =
        Buffer.concat([
            cipher.update(
                plaintext,
                "utf8"
            ),

            cipher.final()
        ]);


    return {

        format:
            "otp-shelter",

        version: 2,


        kdf,


        encryption: {

            algorithm:
                "aes-256-gcm",

            iv:
                iv.toString(
                    "base64"
                ),

            tag:
                cipher
                    .getAuthTag()
                    .toString(
                        "base64"
                    )
        },


        data:
            ciphertext.toString(
                "base64"
            )
    };
}


/*
|--------------------------------------------------------------------------
| Vault decryption
|--------------------------------------------------------------------------
*/

function decryptVault(
    raw,
    password
) {

    if (
        !raw ||
        typeof raw !==
        "object"
    ) {
        throw new Error(
            "Invalid vault file."
        );
    }


    if (
        raw.format !==
        "otp-shelter"
    ) {
        throw new Error(
            "Invalid vault format."
        );
    }


    if (
        raw.version !== 2
    ) {
        throw new Error(
            "Unsupported vault version."
        );
    }


    if (
        !raw.kdf ||
        raw.kdf.name !==
        "scrypt"
    ) {
        throw new Error(
            "Unsupported key derivation."
        );
    }


    if (
        !raw.encryption ||
        raw.encryption.algorithm !==
        "aes-256-gcm"
    ) {
        throw new Error(
            "Unsupported encryption."
        );
    }


    if (
        !raw.data ||
        !raw.encryption.iv ||
        !raw.encryption.tag ||
        !raw.kdf.salt
    ) {
        throw new Error(
            "Invalid encrypted vault."
        );
    }


    const salt =
        Buffer.from(
            raw.kdf.salt,
            "base64"
        );


    if (
        salt.length < 16
    ) {
        throw new Error(
            "Invalid vault salt."
        );
    }


    const key =
        deriveKey(
            password,
            salt,
            raw.kdf
        );


    try {

        const aad =
            Buffer.from(
                JSON.stringify({
                    format:
                        "otp-shelter",

                    version: 2,

                    kdf: {
                        name:
                            raw.kdf.name,

                        N:
                            raw.kdf.N,

                        r:
                            raw.kdf.r,

                        p:
                            raw.kdf.p,

                        dkLen:
                            raw.kdf.dkLen
                    },

                    cipher:
                        "aes-256-gcm"
                })
            );


        const decipher =
            crypto.createDecipheriv(
                "aes-256-gcm",
                key,
                Buffer.from(
                    raw.encryption.iv,
                    "base64"
                )
            );


        decipher.setAAD(
            aad
        );


        decipher.setAuthTag(
            Buffer.from(
                raw.encryption.tag,
                "base64"
            )
        );


        const plaintext =
            Buffer.concat([
                decipher.update(
                    Buffer.from(
                        raw.data,
                        "base64"
                    )
                ),

                decipher.final()
            ]);


        const vault =
            JSON.parse(
                plaintext.toString(
                    "utf8"
                )
            );


        validateVault(
            vault
        );


        return {
            vault,
            key
        };

    } catch (error) {

        key.fill(0);

        throw new Error(
            "Unable to unlock vault. Password may be incorrect or the vault may be corrupted."
        );
    }
}


/*
|--------------------------------------------------------------------------
| Read raw vault
|--------------------------------------------------------------------------
*/

function readRawVault() {

    if (
        !fs.existsSync(
            VAULT_FILE
        )
    ) {
        return null;
    }


    const content =
        fs.readFileSync(
            VAULT_FILE,
            "utf8"
        );


    return JSON.parse(
        content
    );
}


/*
|--------------------------------------------------------------------------
| Read unlocked vault
|--------------------------------------------------------------------------
*/

function readVault(
    session
) {

    const raw =
        readRawVault();


    if (!raw) {

        /*
         * First vault.
         */

        return createEmptyVault();
    }


    /*
     * The session key already proves
     * authentication.
     *
     * We decrypt using the session key.
     */

    return decryptWithKey(
        raw,
        session.key
    );
}


/*
|--------------------------------------------------------------------------
| Decrypt using derived session key
|--------------------------------------------------------------------------
*/

function decryptWithKey(
    raw,
    key
) {

    const aad =
        Buffer.from(
            JSON.stringify({
                format:
                    "otp-shelter",

                version: 2,

                kdf: {
                    name:
                        raw.kdf.name,

                    N:
                        raw.kdf.N,

                    r:
                        raw.kdf.r,

                    p:
                        raw.kdf.p,

                    dkLen:
                        raw.kdf.dkLen
                },

                cipher:
                    "aes-256-gcm"
            })
        );


    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            Buffer.from(
                raw.encryption.iv,
                "base64"
            )
        );


    decipher.setAAD(
        aad
    );


    decipher.setAuthTag(
        Buffer.from(
            raw.encryption.tag,
            "base64"
        )
    );


    const plaintext =
        Buffer.concat([
            decipher.update(
                Buffer.from(
                    raw.data,
                    "base64"
                )
            ),

            decipher.final()
        ]);


    const vault =
        JSON.parse(
            plaintext.toString(
                "utf8"
            )
        );


    validateVault(
        vault
    );


    return vault;
}


/*
|--------------------------------------------------------------------------
| Write vault
|--------------------------------------------------------------------------
*/

function writeVault(
    vault,
    session
) {

    validateVault(
        vault
    );


    const existing =
        readRawVault();


    const encrypted =
        encryptVault(
            vault,
            session.key,

            existing?.kdf ||
            null
        );


    const tmp =
        path.join(
            DATA_DIR,

            `.vault-${process.pid}-${crypto.randomUUID()}.tmp`
        );


    fs.writeFileSync(
        tmp,

        JSON.stringify(
            encrypted,
            null,
            2
        ),

        {
            mode: 0o600
        }
    );


    fs.renameSync(
        tmp,
        VAULT_FILE
    );


    fs.chmodSync(
        VAULT_FILE,
        0o600
    );
}


/*
|--------------------------------------------------------------------------
| Vault write lock
|--------------------------------------------------------------------------
*/

let vaultQueue =
    Promise.resolve();


function withVaultLock(fn) {

    const operation =
        vaultQueue.then(
            fn,
            fn
        );


    vaultQueue =
        operation.catch(
            () => { }
        );


    return operation;
}


/*
|--------------------------------------------------------------------------
| Base32
|--------------------------------------------------------------------------
*/

function normalizeSecret(value) {

    return String(
        value || ""
    )
        .trim()
        .replace(
            /[\s-]/g,
            ""
        )
        .replace(
            /=+$/g,
            ""
        )
        .toUpperCase();
}


function validateBase32(value) {

    const secret =
        normalizeSecret(
            value
        );


    if (!secret) {

        throw new Error(
            "Enter a TOTP secret."
        );
    }


    if (
        !/^[A-Z2-7]+$/.test(
            secret
        )
    ) {

        throw new Error(
            "Invalid Base32 secret."
        );
    }


    if (
        secret.length < 16
    ) {

        throw new Error(
            "Base32 secret is too short."
        );
    }


    const remainder =
        secret.length % 8;


    if (
        [
            1,
            3,
            6
        ].includes(
            remainder
        )
    ) {

        throw new Error(
            "Invalid Base32 secret length."
        );
    }


    return secret;
}


function base32Decode(value) {

    const secret =
        normalizeSecret(
            value
        );


    const alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";


    let bits =
        "";


    const bytes =
        [];


    for (
        const char of secret
    ) {

        const index =
            alphabet.indexOf(
                char
            );


        if (
            index === -1
        ) {

            throw new Error(
                "Invalid Base32 secret."
            );
        }


        bits +=
            index
                .toString(2)
                .padStart(
                    5,
                    "0"
                );
    }


    for (
        let i = 0;
        i + 8 <= bits.length;
        i += 8
    ) {

        bytes.push(
            parseInt(
                bits.slice(
                    i,
                    i + 8
                ),
                2
            )
        );
    }


    const buffer =
        Buffer.from(
            bytes
        );


    if (
        !buffer.length
    ) {

        throw new Error(
            "Invalid Base32 secret."
        );
    }


    return buffer;
}


/*
|--------------------------------------------------------------------------
| TOTP configuration
|--------------------------------------------------------------------------
*/

function validateTotpConfig(site) {

    const algorithm =
        String(
            site.algorithm ||
            "SHA1"
        )
            .toUpperCase();


    if (
        ![
            "SHA1",
            "SHA256",
            "SHA512"
        ].includes(
            algorithm
        )
    ) {

        throw new Error(
            "Invalid TOTP algorithm."
        );
    }


    const digits =
        Number(
            site.digits || 6
        );


    if (
        ![
            6,
            8
        ].includes(
            digits
        )
    ) {

        throw new Error(
            "TOTP supports only 6 or 8 digits."
        );
    }


    const period =
        Number(
            site.period || 30
        );


    if (
        !Number.isInteger(
            period
        ) ||

        period < 5 ||

        period > 300
    ) {

        throw new Error(
            "Invalid TOTP period."
        );
    }


    return {
        algorithm,
        digits,
        period
    };
}


/*
|--------------------------------------------------------------------------
| TOTP generation
|--------------------------------------------------------------------------
*/

function generateCodeAt(
    site,
    timestamp = Date.now()
) {

    const config =
        validateTotpConfig(
            site
        );


    const secret =
        base32Decode(
            site.secret
        );


    const counter =
        Math.floor(
            timestamp /
            1000 /
            config.period
        );


    const buffer =
        Buffer.alloc(
            8
        );


    buffer.writeBigUInt64BE(
        BigInt(
            counter
        )
    );


    const hmac =
        crypto
            .createHmac(
                config
                    .algorithm
                    .toLowerCase(),

                secret
            )
            .update(
                buffer
            )
            .digest();


    const offset =
        hmac[
        hmac.length - 1
        ] &
        0x0f;


    const binary =
        (
            (
                hmac[offset] &
                0x7f
            ) << 24
        ) |

        (
            hmac[
            offset + 1
            ] << 16
        ) |

        (
            hmac[
            offset + 2
            ] << 8
        ) |

        hmac[
        offset + 3
        ];


    const modulo =
        10 **
        config.digits;


    return String(
        binary %
        modulo
    )
        .padStart(
            config.digits,
            "0"
        );
}


function generateCode(site) {

    return generateCodeAt(
        site,
        Date.now()
    );
}


function validateTotpSecret(site) {

    const config =
        validateTotpConfig(
            site
        );


    const secret =
        base32Decode(
            site.secret
        );


    if (
        !secret.length
    ) {

        throw new Error(
            "Invalid TOTP secret."
        );
    }


    const code =
        generateCode(
            site
        );


    if (
        !new RegExp(
            `^\\d{${config.digits}}$`
        ).test(
            code
        )
    ) {

        throw new Error(
            "Unable to generate TOTP."
        );
    }


    return true;
}


/*
|--------------------------------------------------------------------------
| otpauth parser
|--------------------------------------------------------------------------
*/

function parseOtpAuth(uri) {

    let url;


    try {

        url =
            new URL(uri);

    } catch {

        throw new Error(
            "Invalid otpauth URI."
        );
    }


    if (
        url.protocol !==
        "otpauth:"
    ) {

        throw new Error(
            "URI must start with otpauth://"
        );
    }


    if (
        url.hostname
            .toLowerCase() !==
        "totp"
    ) {

        throw new Error(
            "Only TOTP accounts are supported."
        );
    }


    const secret =
        validateBase32(
            url.searchParams.get(
                "secret"
            )
        );


    const label =
        decodeURIComponent(
            url.pathname.replace(
                /^\/+/,
                ""
            )
        );


    let issuerFromLabel =
        "";


    let accountFromLabel =
        label;


    if (
        label.includes(":")
    ) {

        const index =
            label.indexOf(
                ":"
            );


        issuerFromLabel =
            label.substring(
                0,
                index
            );


        accountFromLabel =
            label.substring(
                index + 1
            );
    }


    const issuer =
        url.searchParams.get(
            "issuer"
        ) ||

        issuerFromLabel ||

        "";


    const algorithm =
        (
            url.searchParams.get(
                "algorithm"
            ) ||

            "SHA1"
        )
            .toUpperCase();


    const digits =
        Number(
            url.searchParams.get(
                "digits"
            ) ||

            6
        );


    const period =
        Number(
            url.searchParams.get(
                "period"
            ) ||

            30
        );


    const item = {

        secret,

        name:
            issuer ||

            accountFromLabel ||

            "TOTP Account",

        account:
            accountFromLabel ||

            "",

        issuer,

        algorithm,

        digits,

        period
    };


    validateTotpSecret(
        item
    );


    return item;
}


/*
|--------------------------------------------------------------------------
| Input parser
|--------------------------------------------------------------------------
*/

function parseInput(
    input,
    manualName = ""
) {

    const value =
        String(
            input || ""
        )
            .trim();


    if (!value) {

        throw new Error(
            "Enter a secret or an otpauth URI."
        );
    }


    let item;


    if (
        value
            .toLowerCase()
            .startsWith(
                "otpauth://"
            )
    ) {

        item =
            parseOtpAuth(
                value
            );


        if (
            manualName.trim()
        ) {

            item.name =
                manualName.trim();
        }

    } else {

        const secret =
            validateBase32(
                value
            );


        item = {

            secret,

            name:
                manualName.trim() ||
                "New account",

            account:
                "",

            issuer:
                "",

            algorithm:
                "SHA1",

            digits:
                6,

            period:
                30
        };


        validateTotpSecret(
            item
        );
    }


    return item;
}


/*
|--------------------------------------------------------------------------
| Public site
|--------------------------------------------------------------------------
*/

function publicSite(site) {

    const {
        secret,
        ...safe
    } = site;

    return safe;
}


/*
|--------------------------------------------------------------------------
| Duplicate detection
|--------------------------------------------------------------------------
*/

function isDuplicate(
    vault,
    site
) {

    return vault.sites.some(
        existing =>

            existing.secret ===
            site.secret
    );
}


/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/


/*
|--------------------------------------------------------------------------
| Check vault status
|--------------------------------------------------------------------------
*/

app.get(
    "/api/status",

    (req, res) => {

        const session =
            getSession(req);


        res.json({

            ok: true,

            vaultExists:
                fs.existsSync(
                    VAULT_FILE
                ),

            authenticated:
                Boolean(
                    session
                )
        });
    }
);


/*
|--------------------------------------------------------------------------
| Create vault
|--------------------------------------------------------------------------
|
| First-time password creation.
|
*/

app.post(
    "/api/setup",

    async (
        req,
        res
    ) => {

        try {

            await withVaultLock(
                async () => {

                    if (
                        fs.existsSync(
                            VAULT_FILE
                        )
                    ) {

                        throw new Error(
                            "Vault already exists."
                        );
                    }


                    const password =
                        validatePassword(
                            req.body.password
                        );


                    const salt =
                        crypto.randomBytes(
                            16
                        );


                    const key =
                        deriveKey(
                            password,
                            salt
                        );


                    const backupKey =
                        deriveBackupKey(password);

                    const vault =
                        createEmptyVault();


                    const encrypted =
                        encryptVault(
                            vault,
                            key,
                            {
                                salt:
                                    salt.toString(
                                        "base64"
                                    ),

                                N: 32768,
                                r: 8,
                                p: 1,
                                dkLen: 32
                            }
                        );


                    fs.writeFileSync(
                        VAULT_FILE,

                        JSON.stringify(
                            encrypted,
                            null,
                            2
                        ),

                        {
                            mode: 0o600
                        }
                    );


                    fs.chmodSync(
                        VAULT_FILE,
                        0o600
                    );


                    /*
                     * Password is no longer needed.
                     * Only derived key goes into session.
                     */

                    const sessionId =
                        createSession(
                            key,
                            backupKey
                        );


                    res.cookie(
                        SESSION_COOKIE,

                        sessionId,

                        {

                            httpOnly:
                                true,

                            sameSite:
                                "strict",

                            secure:
                                false,

                            maxAge:
                                SESSION_TIMEOUT,

                            path:
                                "/"
                        }
                    );


                    res
                        .status(201)
                        .json({
                            ok: true
                        });
                }
            );

        } catch (
        error
        ) {

            res
                .status(400)
                .json({
                    error:
                        error.message
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Login rate limiting
|--------------------------------------------------------------------------
*/

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: "Too many login attempts. Please try again in 15 minutes."
    }
});


/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

app.post(
    "/api/login",
    loginLimiter,

    (
        req,
        res
    ) => {

        try {

            if (
                !fs.existsSync(
                    VAULT_FILE
                )
            ) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Vault does not exist."
                    });
            }


            const password =
                validatePassword(
                    req.body.password
                );


            const backupKey =
                deriveBackupKey(password);

            const raw =
                readRawVault();


            /*
             * decryptVault validates the password
             * through AES-GCM authentication.
             */

            const result =
                decryptVault(
                    raw,
                    password
                );


            /*
             * We don't need to keep plaintext vault.
             *
             * Only the derived key remains in memory.
             */

            const sessionId =
                createSession(
                    result.key,
                    backupKey
                );


            res.cookie(
                SESSION_COOKIE,

                sessionId,

                {

                    httpOnly:
                        true,

                    sameSite:
                        "strict",

                    secure:
                        false,

                    maxAge:
                        SESSION_TIMEOUT,

                    path:
                        "/"
                }
            );


            res.json({
                ok: true
            });

        } catch {

            /*
             * Avoid giving attackers detailed
             * information about password failures.
             */

            res
                .status(401)
                .json({
                    error:
                        "Unable to unlock vault."
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Change master password
|--------------------------------------------------------------------------
*/

app.post(
    "/api/change-password",
    requireAuth,
    async (req, res) => {
        try {
            const currentPassword = validatePassword(req.body.currentPassword);
            const newPassword = validatePassword(req.body.newPassword);

            if (currentPassword === newPassword) {
                throw new Error("The new password must be different from the current password.");
            }

            await withVaultLock(async () => {
                const raw = readRawVault();
                const verified = decryptVault(raw, currentPassword);
                const vault = verified.vault;
                const oldKey = verified.key;
                const newSalt = crypto.randomBytes(16);
                const newKey = deriveKey(newPassword, newSalt);
                const newBackupKey = deriveBackupKey(newPassword);

                try {
                    const encrypted = encryptVault(vault, newKey, {
                        salt: newSalt.toString("base64"),
                        N: 32768, r: 8, p: 1, dkLen: 32
                    });
                    const tmp = path.join(DATA_DIR, `.vault-${process.pid}-${crypto.randomUUID()}.tmp`);
                    fs.writeFileSync(tmp, JSON.stringify(encrypted, null, 2), { mode: 0o600 });
                    fs.renameSync(tmp, VAULT_FILE);
                    fs.chmodSync(VAULT_FILE, 0o600);

                    const stored = sessions.get(req.session.id);
                    if (!stored) throw new Error("Session expired.");
                    try { stored.key.fill(0); } catch { }
                    try { stored.backupKey?.fill(0); } catch { }
                    stored.key = newKey;
                    stored.backupKey = newBackupKey;
                    stored.lastUsed = Date.now();
                    invalidateOtherSessions(req.session.id);
                } catch (error) {
                    newKey.fill(0);
                    newBackupKey.fill(0);
                    throw error;
                } finally {
                    oldKey.fill(0);
                }
            });

            res.json({ ok: true });
        } catch (error) {
            res.status(400).json({ error: error.message || "Unable to change password." });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.post(
    "/api/logout",

    (
        req,
        res
    ) => {

        const cookies =
            parseCookies(
                req
            );


        const sessionId =
            cookies[
            SESSION_COOKIE
            ];


        if (
            sessionId
        ) {

            destroySession(
                sessionId
            );
        }


        res.clearCookie(
            SESSION_COOKIE,
            {
                path: "/"
            }
        );


        res.json({
            ok: true
        });
    }
);


/*
|--------------------------------------------------------------------------
| GET accounts
|--------------------------------------------------------------------------
*/

app.get(
    "/api/sites",

    requireAuth,

    (
        req,
        res
    ) => {

        try {

            const vault =
                readVault(
                    req.session
                );


            res.json(
                vault.sites.map(
                    publicSite
                )
            );

        } catch (
        error
        ) {

            res
                .status(500)
                .json({
                    error:
                        "Unable to read vault."
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Add account
|--------------------------------------------------------------------------
*/

app.post(
    "/api/sites",

    requireAuth,

    async (
        req,
        res
    ) => {

        try {

            const parsed =
                parseInput(
                    req.body.input,
                    req.body.name
                );


            const site =
                await withVaultLock(
                    async () => {

                        const vault =
                            readVault(
                                req.session
                            );


                        if (
                            isDuplicate(
                                vault,
                                parsed
                            )
                        ) {

                            const error =
                                new Error(
                                    "This TOTP secret already exists in the vault."
                                );

                            error.status =
                                409;

                            throw error;
                        }


                        const site = {

                            id:
                                crypto.randomUUID(),

                            ...parsed,

                            createdAt:
                                new Date()
                                    .toISOString()
                        };


                        vault.sites.push(
                            site
                        );


                        writeVault(
                            vault,
                            req.session
                        );


                        return site;
                    }
                );


            res
                .status(201)
                .json(
                    publicSite(
                        site
                    )
                );

        } catch (
        error
        ) {

            res
                .status(
                    error.status ||
                    400
                )
                .json({
                    error:
                        error.message
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Edit account name
|--------------------------------------------------------------------------
*/

app.patch(
    "/api/sites/:id",

    requireAuth,

    async (
        req,
        res
    ) => {

        try {

            const name =
                String(
                    req.body.name ||
                    ""
                )
                    .trim();


            if (!name) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Account name cannot be empty."
                    });
            }


            if (
                name.length > 100
            ) {

                return res
                    .status(400)
                    .json({
                        error:
                            "Account name is too long."
                    });
            }


            const site =
                await withVaultLock(
                    async () => {

                        const vault =
                            readVault(
                                req.session
                            );


                        const site =
                            vault.sites.find(
                                site =>

                                    site.id ===
                                    req.params.id
                            );


                        if (!site) {

                            const error =
                                new Error(
                                    "Account not found."
                                );

                            error.status =
                                404;

                            throw error;
                        }


                        site.name =
                            name;


                        writeVault(
                            vault,
                            req.session
                        );


                        return site;
                    }
                );


            res.json(
                publicSite(
                    site
                )
            );

        } catch (
        error
        ) {

            res
                .status(
                    error.status ||
                    500
                )
                .json({
                    error:
                        error.message
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Generate OTP
|--------------------------------------------------------------------------
*/

app.get(
    "/api/sites/:id/otp",

    requireAuth,

    (
        req,
        res
    ) => {

        try {

            const vault =
                readVault(
                    req.session
                );


            const site =
                vault.sites.find(
                    site =>

                        site.id ===
                        req.params.id
                );


            if (!site) {

                return res
                    .status(404)
                    .json({
                        error:
                            "Account not found."
                    });
            }


            const code =
                generateCode(
                    site
                );


            const period =
                site.period ||
                30;


            const now =
                Math.floor(
                    Date.now() /
                    1000
                );


            let seconds =
                period -
                (
                    now %
                    period
                );


            if (
                seconds === 0
            ) {

                seconds =
                    period;
            }


            res.json({

                ...publicSite(
                    site
                ),

                code,

                seconds
            });

        } catch {

            res
                .status(500)
                .json({
                    error:
                        "Unable to generate TOTP."
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Delete account
|--------------------------------------------------------------------------
*/

app.delete(
    "/api/sites/:id",

    requireAuth,

    async (
        req,
        res
    ) => {

        try {

            await withVaultLock(
                async () => {

                    const vault =
                        readVault(
                            req.session
                        );


                    const index =
                        vault.sites.findIndex(
                            site =>

                                site.id ===
                                req.params.id
                        );


                    if (
                        index < 0
                    ) {

                        const error =
                            new Error(
                                "Account not found."
                            );

                        error.status =
                            404;

                        throw error;
                    }


                    vault.sites.splice(
                        index,
                        1
                    );


                    writeVault(
                        vault,
                        req.session
                    );
                }
            );


            res.json({
                ok: true
            });

        } catch (
        error
        ) {

            res
                .status(
                    error.status ||
                    500
                )
                .json({
                    error:
                        error.message
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Export encrypted vault
|--------------------------------------------------------------------------
|
| This is the ONLY export format.
|
*/

app.get(
    "/api/export",

    requireAuth,

    (
        req,
        res
    ) => {

        if (
            !fs.existsSync(
                VAULT_FILE
            )
        ) {

            return res
                .status(404)
                .json({
                    error:
                        "Vault is empty."
                });
        }


        try {
            const vault = readVault(req.session);

            const backup = encryptVault(
                vault,
                req.session.backupKey,
                {
                    salt: BACKUP_SALT.toString("base64"),
                    N: 32768, r: 8, p: 1, dkLen: 32
                }
            );

            res.setHeader(
                "Content-Disposition",
                "attachment; filename=otp-shelter-vault.json"
            );
            res.type("application/json").send(JSON.stringify(backup, null, 2));
        } catch {
            res.status(500).json({ error: "Unable to export vault." });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Import encrypted vault
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| The imported vault contains its own salt.
|
| Therefore:
|
| current password
| +
| imported vault salt
|
| can derive the correct imported key.
|
*/


app.post(
    "/api/import",

    requireAuth,

    async (
        req,
        res
    ) => {

        try {

            const importedRaw =
                req.body.vault;

            if (!importedRaw || typeof importedRaw !== "object") {
                throw new Error("Invalid backup.");
            }

            /*
             * The authenticated session already holds a portable backup key
             * derived during login. No password is requested again.
             */
            const importedVault =
                decryptWithKey(
                    importedRaw,
                    req.session.backupKey
                );

            const imported = { vault: importedVault };


            const result =
                await withVaultLock(
                    async () => {

                        const vault =
                            readVault(
                                req.session
                            );


                        let importedCount =
                            0;

                        let skipped =
                            0;


                        for (
                            const raw of
                            imported.vault.sites
                        ) {

                            try {

                                validateBase32(
                                    raw.secret
                                );


                                validateTotpConfig(
                                    raw
                                );


                                validateTotpSecret(
                                    raw
                                );


                                if (
                                    isDuplicate(
                                        vault,
                                        raw
                                    )
                                ) {

                                    skipped++;

                                    continue;
                                }


                                vault.sites.push({

                                    id:
                                        crypto.randomUUID(),

                                    name:
                                        raw.name ||
                                        "TOTP Account",

                                    account:
                                        raw.account ||
                                        "",

                                    issuer:
                                        raw.issuer ||
                                        "",

                                    secret:
                                        normalizeSecret(
                                            raw.secret
                                        ),

                                    algorithm:
                                        raw.algorithm ||
                                        "SHA1",

                                    digits:
                                        raw.digits ||
                                        6,

                                    period:
                                        raw.period ||
                                        30,

                                    createdAt:
                                        raw.createdAt ||
                                        new Date()
                                            .toISOString()
                                });


                                importedCount++;

                            } catch {

                                skipped++;
                            }
                        }


                        writeVault(
                            vault,
                            req.session
                        );


                        return {

                            imported:
                                importedCount,

                            skipped
                        };
                    }
                );


            res.json({

                ok: true,

                ...result
            });

        } catch {

            res
                .status(400)
                .json({
                    error:
                        "Unable to import vault. The backup may use a different master password or be corrupted."
                });
        }
    }
);


/*
|--------------------------------------------------------------------------
| Session cleanup
|--------------------------------------------------------------------------
*/

setInterval(
    () => {

        const now =
            Date.now();


        for (
            const [
                sessionId,
                session
            ] of sessions
        ) {

            if (

                now -
                session.lastUsed >

                SESSION_TIMEOUT

            ) {

                destroySession(
                    sessionId,
                    session
                );
            }
        }

    },

    60 * 1000
);


/*
|--------------------------------------------------------------------------
| Start
|--------------------------------------------------------------------------
*/

app.listen(
    PORT,
    () => {

        console.log(
            `OTP-Shelter listening on port ${PORT}`
        );


        console.log(
            `Vault: ${VAULT_FILE}`
        );
    }
);

