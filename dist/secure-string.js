"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const util = require("util");
const buffer_1 = require("buffer");
const pbkdf2 = util.promisify(crypto.pbkdf2);
exports.AES192 = {
    algorithm: 'aes192', keyLength: 24, ivLength: 16, digest: 'sha256', iterations: 100000
};
exports.AES256 = {
    algorithm: 'aes256', keyLength: 32, ivLength: 16, digest: 'sha256', iterations: 100000
};
function init(cipher, secret, salt, { algorithm, keyLength, ivLength, digest, iterations }) {
    return __awaiter(this, void 0, void 0, function* () {
        const keyAndIv = yield pbkdf2(secret, salt, iterations, keyLength + ivLength, digest);
        const key = keyAndIv.slice(0, keyLength);
        const iv = keyAndIv.slice(keyLength, keyLength + ivLength);
        return cipher(algorithm, key, iv);
    });
}
class SecureString {
    constructor(encrypted, algorithm) {
        this.encrypted = encrypted;
        this.algorithm = algorithm;
    }
    static encrypt(plaintext, secret, salt, algorithm = exports.AES256) {
        return __awaiter(this, void 0, void 0, function* () {
            const encrypter = yield init(crypto.createCipheriv, secret, salt, algorithm);
            let encrypted = '';
            encrypted += encrypter.update(plaintext, 'utf8', 'base64');
            encrypted += encrypter.final('base64');
            return new SecureString(encrypted, algorithm);
        });
    }
    static decrypt(encrypted, secret, salt, algorithm = exports.AES256) {
        return __awaiter(this, void 0, void 0, function* () {
            const decrypter = yield init(crypto.createDecipheriv, secret, salt, algorithm);
            let decrypted = '';
            decrypted += decrypter.update(encrypted, 'base64', 'utf8');
            decrypted += decrypter.final('utf8');
            return decrypted;
        });
    }
    decrypt(secret, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield SecureString.decrypt(this.encrypted, secret, salt, this.algorithm);
        });
    }
    valueOf() {
        return this.encrypted;
    }
    toString() {
        return this.encrypted;
    }
    toBuffer() {
        return buffer_1.Buffer.from(this.encrypted, 'base64');
    }
}
exports.SecureString = SecureString;
function encrypt(plaintext, secret, salt, algorithm = exports.AES256) {
    if (this instanceof encrypt) {
        throw new Error("Use `SecureString.encrypt(...)` or `new SecureString(...)");
    }
    return SecureString.encrypt.apply(undefined, arguments);
}
exports.default = encrypt;
module.exports = Object.assign(encrypt, exports);
