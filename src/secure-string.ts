import * as crypto from 'crypto';
import * as util from 'util';
import {Cipher, Decipher} from 'crypto';
import { Buffer } from 'buffer';

const pbkdf2 = util.promisify(crypto.pbkdf2);

export type algorithm = {
    algorithm:  string,
    keyLength:  number,
    ivLength:   number,
    digest:     string,
    iterations: number,
}

export const AES192: algorithm = {
    algorithm: 'aes192', keyLength: 24, ivLength: 16, digest: 'sha256', iterations: 100000
};

export const AES256: algorithm = {
    algorithm: 'aes256', keyLength: 32, ivLength: 16, digest: 'sha256', iterations: 100000
};

async function init<R extends Cipher | Decipher>(cipher: (...args:any[]) => R, secret: string | Buffer, salt: string | Buffer, {algorithm, keyLength, ivLength, digest, iterations}: algorithm): Promise<R> {

    const keyAndIv = await pbkdf2(secret, salt, iterations, keyLength + ivLength, digest);

    const key = keyAndIv.slice(0, keyLength);
    const iv  = keyAndIv.slice(keyLength, keyLength + ivLength);

    return cipher(algorithm, key, iv);
}

export class SecureString {

    static async encrypt(plaintext: string, secret: string | Buffer, salt: string | Buffer, algorithm: algorithm = AES256): Promise<SecureString> {

        const encrypter = await init(crypto.createCipheriv, secret, salt, algorithm);

        let encrypted = '';
        encrypted += encrypter.update(plaintext, 'utf8', 'base64');
        encrypted += encrypter.final('base64');

        return new SecureString(encrypted, algorithm);

    }

    static async decrypt(encrypted: string, secret: string | Buffer, salt: string | Buffer, algorithm: algorithm = AES256): Promise<string> {

        const decrypter = await init(crypto.createDecipheriv, secret, salt, algorithm);

        let decrypted = '';
        decrypted += decrypter.update(encrypted, 'base64', 'utf8');
        decrypted += decrypter.final('utf8');

        return decrypted;

    }


    constructor(private encrypted: string, private algorithm: algorithm) {}


    public async decrypt(secret: string | Buffer, salt: string | Buffer) {
        return await SecureString.decrypt(this.encrypted, secret, salt, this.algorithm);
    }


    public valueOf() {
        return this.encrypted;
    }

    public toString() {
        return this.encrypted;
    }

    public toBuffer(): Buffer {
        return Buffer.from(this.encrypted, 'base64');
    }

}

export default function encrypt(plaintext: string, secret: string | Buffer, salt: string | Buffer, algorithm: algorithm = AES256) {

    if (this instanceof encrypt) {
        throw new Error("Use `SecureString.encrypt(...)` or `new SecureString(...)") ;
    }

    return SecureString.encrypt.apply(undefined, arguments);

}

module.exports = Object.assign(encrypt, exports);