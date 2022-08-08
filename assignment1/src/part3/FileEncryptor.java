package part3;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/***
 * Leon Menzies - 300543278
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int COUNT = 1000;

    /***
     * The Main method Checks the args to decide if encryption or decryption is being preformed and
     * then call teh corresponding method
     *
     * @param args - The arguments passed from console inputs
     * @throws Exception - Exceptions thrown by internal methods
     */
    public static void main(String[] args) throws Exception {
        new FileEncryptor().run(args);
    }

    public void run(String[] args) throws Exception {
        if (Objects.equals(args[0], "enc")) {
            if (args.length != 4) {
                error("Invalid number of inputs");
            }

            //Generate the IV
            SecureRandom sr = new SecureRandom();
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector);

            enc(args[1].toCharArray(), initVector, args[2], args[3]);
        } else if (Objects.equals(args[0], "dec")) {
            if (args.length != 4) {
                error("Invalid number of inputs");
            }

            dec(args[1].toCharArray(), args[2], args[3]);
        } else {
            System.out.println("Invalid instruction type");
        }
    }

    /***
     * The Method is used to encrypt the file at the given directory and save it at the
     * location specified
     * @param password - The password give by the user which will be used to create a secret key
     * @param initVector - The initial vector for encrypting the file
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void enc(char[] password, byte[] initVector, String inputDir, String outputDir) throws Exception {

        // Salt
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, COUNT, iv);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        System.out.println("Secret key is " + bytesToHex(pbeKey.getEncoded()).replaceAll("\\s+", ""));

        try (FileInputStream fin = new FileInputStream(inputDir);
             FileOutputStream fout = new FileOutputStream(outputDir);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            //Write the IV to the file
            fout.write(initVector);
            //Write salt to the file
            fout.write(salt);

            final byte[] bytes = new byte[1024];
            for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }
        LOG.info("Encryption finished, saved at " + outputDir);
    }

    /***
     * The Method is used to decrypt the file at the given directory and save it at the
     * location specified
     * @param password - The password used to encrypt the file
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void dec(char[] password, String inputDir, String outputDir) throws Exception {

        final byte[] ivs = new byte[16];
        final byte[] salt = new byte[16];

        try (InputStream encryptedData = new FileInputStream(inputDir)) {

            //Read the IV from the file
            encryptedData.read(ivs);

            //read the salt form the file
            encryptedData.read(salt);

            IvParameterSpec iv = new IvParameterSpec(ivs);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, COUNT, iv);
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

            //Do the decryption
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher); OutputStream decryptedOut = new FileOutputStream(outputDir)) {

                final byte[] bytes = new byte[1024];
                for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                    decryptedOut.write(bytes, 0, length);
                }
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
    }

    public static void error(String message) {
        System.out.println(message);
        System.exit(0);
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}