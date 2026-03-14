let fs = require('fs')
let path = require('path')
let crypto = require('crypto')
let jwt = require('jsonwebtoken')

let ACCESS_TOKEN_EXPIRES_IN = '1h'
let KEY_DIR = path.join(__dirname, '..', 'keys')
let PRIVATE_KEY_PATH = path.join(KEY_DIR, 'private.key')
let PUBLIC_KEY_PATH = path.join(KEY_DIR, 'public.key')

function normalizePem(value) {
    if (!value) {
        return ''
    }
    return value.replace(/\\n/g, '\n')
}

function loadKeysFromEnv() {
    let privateKey = normalizePem(process.env.JWT_PRIVATE_KEY)
    let publicKey = normalizePem(process.env.JWT_PUBLIC_KEY)

    if (privateKey && publicKey) {
        return {
            privateKey,
            publicKey
        }
    }

    if ((privateKey && !publicKey) || (!privateKey && publicKey)) {
        throw new Error('JWT_PRIVATE_KEY va JWT_PUBLIC_KEY phai duoc cung cap day du')
    }

    return null
}

function loadKeysFromFiles() {
    if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
        return null
    }

    return {
        privateKey: fs.readFileSync(PRIVATE_KEY_PATH, 'utf8'),
        publicKey: fs.readFileSync(PUBLIC_KEY_PATH, 'utf8')
    }
}

function generateAndStoreKeys() {
    let generated = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    })

    fs.mkdirSync(KEY_DIR, { recursive: true })
    fs.writeFileSync(PRIVATE_KEY_PATH, generated.privateKey, { encoding: 'utf8', mode: 0o600 })
    fs.writeFileSync(PUBLIC_KEY_PATH, generated.publicKey, { encoding: 'utf8' })

    return generated
}

function getKeys() {
    let envKeys = loadKeysFromEnv()
    if (envKeys) {
        return envKeys
    }

    let fileKeys = loadKeysFromFiles()
    if (fileKeys) {
        return fileKeys
    }

    return generateAndStoreKeys()
}

let keys = getKeys()

module.exports = {
    signAccessToken: function (payload) {
        return jwt.sign(payload, keys.privateKey, {
            algorithm: 'RS256',
            expiresIn: ACCESS_TOKEN_EXPIRES_IN
        })
    },
    verifyAccessToken: function (token) {
        return jwt.verify(token, keys.publicKey, {
            algorithms: ['RS256']
        })
    }
}