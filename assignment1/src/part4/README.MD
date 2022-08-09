## How to run

### encryption

Parameters:

1. Type: enc
2. Encryption type: AES or Blowfish
3. Key length: AES - 128, 192, 256 Blowfish - 32 to 448
4. A password for the encryption: password (Example)
5. Directory of file being encrypted: *****.txt
6. Directory where ciphertext should be saved: *****.enc

Example - java FileEncryptor.java enc AES 192 password plaintext.txt ciphertext.enc

### info

Parameters:

1. Type: info
2. Directory of the encrypted file: *****.enc

Example - java FileEncryptor.java info ciphertext.enc

### decryption

Parameters:

1. Type: dec
2. The password used for the encrypting the file: password (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec password ciphertext.enc decrypted.txt

