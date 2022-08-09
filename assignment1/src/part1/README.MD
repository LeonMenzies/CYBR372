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
2. Key: AC4BB15F51F40716EF952A082381FC83 (Example)
3. IV: 0CA93F3CF5BED40073FA8546AF8185FB (Example)
4. Directory of the encrypted file: *****.enc
5. Directory where the decrypted file should be saved: *****.txt

Example - java FileEncryptor.java dec AC4BB15F51F40716EF952A082381FC83 0CA93F3CF5BED40073FA8546AF8185FB ciphertext.enc
decrypted.txt


