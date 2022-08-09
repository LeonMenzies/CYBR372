## How to run

### encryption

Parameters:

1. Type: enc
2. A key for the encryption: 14540134C18B0DE9366DC15FE98118B7 (Example)
3. Directory of file being encrypted: *****.txt
4. Directory where ciphertext should be saved: *****.enc

Example - java FileEncryptor.java enc 14540134C18B0DE9366DC15FE98118B7 plaintext.txt ciphertext.enc

### decryption

Parameters:

1. Type: dec
2. The key used for the encryption: 14540134C18B0DE9366DC15FE98118B7 (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec 14540134C18B0DE9366DC15FE98118B7 ciphertext.enc decrypted.txt


