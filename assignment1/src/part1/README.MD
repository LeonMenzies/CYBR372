## How to run

### encryption

Parameters:

1. Type: enc
2. Directory of file being encrypted: *****.txt
3. Directory where ciphertext should be saved: *****.enc

Example - java FileEncryptor.java enc plaintext.txt ciphertext.enc

### decryption

Parameters:

1. Type: dec
2. Key: bTJWxTZ3we9wSJsQYd8GcQ== (Example)
3. IV: CvC9iKJ4K5IX3SJzxIq3Cw== (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec bTJWxTZ3we9wSJsQYd8GcQ== CvC9iKJ4K5IX3SJzxIq3Cw== ciphertext.enc decrypted.txt


