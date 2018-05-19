# SecureString

A secure string for node.

## Install

```
npm install @xbaun/secure-string
```

## Usage

For es6 modules:
```javascript

    import { SecureString } from '@xbaun/secure-string';
    
    ...
    
    let encrypted = await SecureString.encrypt("secret text", "password", "salt");
    // YrxsICumyhPx1Yh9DuYNVQ==
    
    await encrypted.decrypt("password", "salt");
    // secret text

```

For commonjs modules:

```javascript

    const SecureString = require('@xbaun/secure-string');
    
    ...
    
    SecureString("secret text", "password", "salt").then((encrypted) => {
    
        console.log(encrypted); // YrxsICumyhPx1Yh9DuYNVQ==
        
        let dec = encrypted.decrypt("password", "salt").then((decrypted) => {
            console.log(decrypted); // secret text
        });
        
    });

```

## API

### Algorithm

The ```SecurString.encrypt``` and ```SecurString.decrypt``` defaults to ```AES256``` as encryption/decryption cipher.

Available ciphers are:
- AES192
- AES256

A cipher is defined as an object with the following properties:

- **algorithm**:  string - The algorithm to use. Supported are all available OpenSSL cipher algorithms. See [```crypto.createCipheriv```](https://nodejs.org/api/crypto.html#crypto_crypto_createcipheriv_algorithm_key_iv_options)
- **keyLength**:  number - The required key length of the cipher algorithm. For AES256 its a length of 256 Bits = 32 Bytes.
- **ivLength**:   number - The required iv length of the cipher algorithm. AES has a block size of 128 Bits = 16 Bytes.
- **digest**:     string - The digest used by pbkdf2.
- **iterations**: number - The number of iterations used by pbkdf2.

##### Example

```javascript
    
    import { SecureString, AES256 } from '@xbaun/secure-string';
    
    ...
    
    let encrypted = await SecureString.encrypt("secret text", "password", "salt", AES256);
    
```

### SecureString

#### encrypt(plaintext: string, secret: string | Buffer, salt: string | Buffer, algorithm: algorithm = AES256): Promise<SecureString>

Encrypts a plaintext message with a given ```secret``` and ```salt```. Returns a base64 encoded ciphertext.

##### Arguments

- **plaintext** - The string to encrypt.
- **secret** - The secret to use for encryption.
- **salt** - A optional salt which will be combined with the secret.
- **algorithm** - Defaults to AES256.

##### Example

```javascript
SecureString.encrypt("secret text", "password", "salt");
```

#### decrypt(encrypted: string, secret: string | Buffer, salt: string | Buffer, algorithm: algorithm = AES256): Promise<string>

Decrypts an encrypted base64 message with a given ```secret``` and ```salt```. Returns the decoded plaintext message. 
On an instance of ```SecureString``` it can be called ```.decrypt("secret", "salt")``` directly.

##### Arguments

- **encrypted** - The base64 encrypted message.
- **secret** - The secret to use for decryption.
- **salt** - A optional salt which will be combined with the secret.
- **algorithm** - Defaults to AES256.

##### Example

```javascript
SecureString.decrypt("YrxsICumyhPx1Yh9DuYNVQ==", "password", "salt");
```

```javascript
let encrypted = await SecureString.encrypt("secret text", "password", "salt");
await encrypted.decrypt("password", "salt");
```