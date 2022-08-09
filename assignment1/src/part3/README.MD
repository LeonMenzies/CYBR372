## How to run

### encryption

Parameters:

1. Type: enc
2. A password for the encryption: password (Example)
3. Directory of file being encrypted: *****.txt
4. Directory where ciphertext should be saved: *****.enc

Example - java FileEncryptor.java enc password plaintext.txt ciphertext.enc

### decryption

Parameters:

1. Type: dec
2. The password used for the encrypting the file: password (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec password ciphertext.enc decrypted.txt

