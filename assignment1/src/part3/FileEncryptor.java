package part3;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
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
     * The main is called when the program is run by the user. It creates a new FileEncryption object and runs it with the given arguments
     *
     * @param args - The arguments passed from console inputs
     */
    public static void main(String[] args) {
        try {
            new FileEncryptor().run(args);
        } catch (Exception e) {
            handleExceptions(e);
        }
    }

    /***
     * This method is on charge of running the first step in the algorithm by reading the users input and
     * @param args - The argument instructions from the user
     * @throws Exception - Exceptions thrown by internal methods which will be handled in a separate method
     */
    public void run(String[] args) throws Exception {
        if (Objects.equals(args[0], "enc")) {
            if (args.length != 4) {
                error("Invalid number of inputs");
            }

            enc(args[1].toCharArray(), args[2], args[3]);
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
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void enc(char[] password, String inputDir, String outputDir) throws Exception {

        // Salt
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] initVector = new byte[16];
        RANDOM.nextBytes(initVector);

        IvParameterSpec iv = new IvParameterSpec(initVector);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, COUNT, iv);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        System.out.println("Secret key is " + bytesToHex(pbeKey.getEncoded()).replaceAll("\\s+", ""));

        try (InputStream fin = Files.newInputStream(Paths.get(inputDir));
             OutputStream fout = Files.newOutputStream(Paths.get((outputDir)));
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            try {
                //Write the IV to the file
                fout.write(initVector);
                //Write salt to the file
                fout.write(salt);

                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }
            } catch (IOException e) {
                handleExceptions(e);
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

        byte[] ivs;
        byte[] salt;
        try (InputStream encryptedData = Files.newInputStream(Paths.get(inputDir))) {

            //Read the IV from the file
            ivs = encryptedData.readNBytes(16);

            //read the salt form the file
            salt = encryptedData.readNBytes(16);

            IvParameterSpec iv = new IvParameterSpec(ivs);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, COUNT, iv);
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_256");
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

            //Do the decryption
            try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher); OutputStream decryptedOut = new FileOutputStream(outputDir)) {

                try {
                    final byte[] bytes = new byte[1024];
                    for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
                        decryptedOut.write(bytes, 0, length);
                    }
                } catch (IOException e) {
                    handleExceptions(e);
                }
            } catch (IOException ex) {
                Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
            }

        } catch (IOException ex) {
            Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }
        LOG.info("Decryption complete, open " + outputDir);
    }

    /***
     * This is a simple method to log error messages to the user and exit the program
     * @param message - The message to be printed
     */
    public static void error(String message) {
        System.out.println(message);
        System.exit(0);
    }

    /***
     * This is used to convert a byte array to hexadecimal
     * @param bytes - Byte array to be converted
     * @return - The hex string that has been created
     */
    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /***
     * This method is used to take any exception that a are thrown and print out a more readable message to the user
     * @param e - The exception that has been thrown else where in the program
     */
    public static void handleExceptions(Exception e) {
        System.out.println(e.getMessage());
    }

}