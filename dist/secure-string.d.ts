/// <reference types="node" />
export declare type algorithm = {
    algorithm: string;
    keyLength: number;
    ivLength: number;
    digest: string;
    iterations: number;
};
export declare const AES192: algorithm;
export declare const AES256: algorithm;
export declare class SecureString {
    private encrypted;
    private algorithm;
    static encrypt(plaintext: string, secret: string | Buffer, salt: string | Buffer, algorithm?: algorithm): Promise<SecureString>;
    static decrypt(encrypted: string, secret: string | Buffer, salt: string | Buffer, algorithm?: algorithm): Promise<string>;
    constructor(encrypted: string, algorithm: algorithm);
    decrypt(secret: string | Buffer, salt: string | Buffer): Promise<string>;
    valueOf(): string;
    toString(): string;
    toBuffer(): Buffer;
}
export default function encrypt(plaintext: string, secret: string | Buffer, salt: string | Buffer, algorithm?: algorithm): any;
