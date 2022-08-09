package part1;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/***
 * Leon Menzies - 300543278
 */
public class FileEncryptor {
    private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    /***
     * The main is called when the program is run by the user. It creates a new FileEncryption object and runs it with the given arguments
     *
     * @param args - The arguments passed from console inputs
     * @throws Exception - Exceptions thrown by internal methods
     */
    public static void main(String[] args) throws Exception {
        new FileEncryptor().run(args);
    }

    /***
     * This method is on charge of running the first step in the algorithm by reading the users input and
     * @param args - The argument instructions from the user
     * @throws Exception - Exceptions thrown by internal methods which will be handled in a seperate method
     */
    public void run(String[] args) throws Exception {
        if (Objects.equals(args[0], "enc")) {
            if (args.length != 3) {
                error("Invalid number of inputs");
            }

            //Generate the random keys
            SecureRandom sr = new SecureRandom();
            byte[] key = new byte[16];
            sr.nextBytes(key);
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector);
            System.out.println("Secret key is: " + bytesToHex(key).replaceAll("\\s+", ""));
            System.out.println("IV is: " + bytesToHex(initVector).replaceAll("\\s+", ""));

            enc(key, initVector, args[1], args[2]);
        } else if (Objects.equals(args[0], "dec")) {
            if (args.length != 5) {
                error("Invalid number of inputs");
            }

            dec(HexFormat.of().parseHex(args[1]), HexFormat.of().parseHex(args[2]), args[3], args[4]);
        } else {
            System.out.println("Invalid instruction type");
        }
    }

    /***
     * The Method is used to encrypt the file at the given directory and save it at the
     * location specified
     * @param key - The key used to encrypt the file
     * @param initVector - The initial vector for encrypting the file
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void enc(byte[] key, byte[] initVector, String inputDir, String outputDir) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        try (InputStream fin = new FileInputStream(inputDir); OutputStream fout = new FileOutputStream(outputDir); CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
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
     * @param key - The key used to encrypt the file
     * @param initVector - The initial vector for encrypting the file
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void dec(byte[] key, byte[] initVector, String inputDir, String outputDir) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        try (InputStream encryptedData = new FileInputStream(inputDir); CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher); OutputStream decryptedOut = new FileOutputStream(outputDir)) {
            final byte[] bytes = new byte[1024];
            for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        LOG.info("Decryption complete, open " + outputDir);
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