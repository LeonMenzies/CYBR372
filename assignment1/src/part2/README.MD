## How to run

### encryption

Parameters:

1. Type: enc
2. A key for the encryption: bTJWxTZ3we9wSJsQYd8GcQ== (Example)
3. Directory of file being encrypted: *****.txt
4. Directory where ciphertext should be saved: *****.enc

Example - java FileEncryptor.java enc bTJWxTZ3we9wSJsQYd8GcQ== plaintext.txt ciphertext.enc

### decryption

Parameters:

1. Type: dec
2. The key used for the encryption: bTJWxTZ3we9wSJsQYd8GcQ== (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec bTJWxTZ3we9wSJsQYd8GcQ== ciphertext.enc decrypted.txt


