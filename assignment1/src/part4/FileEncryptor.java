package part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
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
            if (args.length != 6) {
                error("Invalid number of inputs");
            }

            //Default values
            String algorithm = "AES";
            int keyLength = 256;

            //Check for AES, if given make sure key length is valid
            if (Objects.equals(args[1], "AES")) {
                try {
                    keyLength = Integer.parseInt(args[2]);

                    if (!(keyLength == 128 || keyLength == 192 || keyLength == 256)) {
                        error("Invalid key length, must be 128, 192, or 256");
                    }
                } catch (NumberFormatException nfe) {
                    error("Key length must be a number");
                }
                algorithm = args[1];

                //Check for Blowfish, if given make sure key length is valid
            } else if (Objects.equals(args[1], "Blowfish")) {
                try {
                    keyLength = Integer.parseInt(args[2]);

                    if (!(keyLength >= 32 && keyLength <= 448)) {
                        error("Invalid key length, must be between 32 and 448");
                    }
                } catch (NumberFormatException nfe) {
                    error("Key length must be a number");
                }
                algorithm = args[1];
            } else {
                error("Invalid algorithm");
            }

            try {
                keyLength = Integer.parseInt(args[2]);

            } catch (NumberFormatException nfe) {
                error("Key length must be a number");
            }

            enc(algorithm, keyLength, args[3].toCharArray(), args[4], args[5]);
        } else if (Objects.equals(args[0], "dec")) {
            if (args.length != 4) {
                error("Invalid number of inputs");
            }

            dec(args[1].toCharArray(), args[2], args[3]);
        } else if (Objects.equals(args[0], "info")) {
            info(args[1]);
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
    public void enc(String algorithm, int keyLength, char[] password, String inputDir, String outputDir) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");

        byte[] iv = new byte[cipher.getBlockSize()];
        RANDOM.nextBytes(iv);

        // Salt
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        IvParameterSpec ivv = new IvParameterSpec(iv);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, COUNT, keyLength);

        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        SecretKeySpec key = new SecretKeySpec(pbeKey.getEncoded(), algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivv);

        System.out.println("Secret key is " + bytesToHex(key.getEncoded()).replaceAll("\\s+", ""));

        try (InputStream fin = Files.newInputStream(Paths.get(inputDir)); FileOutputStream fout = new FileOutputStream(outputDir, false); CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
        }) {
            try {
                //Write the IV to the file
                fout.write(iv);
                //Write salt to the file
                fout.write(salt);

                final byte[] bytes = new byte[1024];
                for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
                    cipherOut.write(bytes, 0, length);
                }

                //Write meta data to file attributes
                UserDefinedFileAttributeView userDefinedFAView = Files.getFileAttributeView(Paths.get(outputDir), UserDefinedFileAttributeView.class);
                //Write the key to the file meta-data
                userDefinedFAView.write(keyLength + "", Charset.defaultCharset().encode(keyLength + ""));
                //Write the algorithm type to the file meta-data
                userDefinedFAView.write(algorithm, Charset.defaultCharset().encode(algorithm));
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
        byte[] iv;
        byte[] salt;
        try (InputStream encryptedData = Files.newInputStream(Paths.get(inputDir))) {
            //Get the attributes needed to create the key and decrypt the data
            List<String> attList = getAttributes(inputDir);
            Cipher cipher = Cipher.getInstance(attList.get(1) + "/CBC/PKCS5Padding");
            int ivlength = cipher.getBlockSize();
            //Read the IV from the file
            iv = encryptedData.readNBytes(ivlength);

            //read the salt form the file
            salt = encryptedData.readNBytes(16);


            IvParameterSpec ivv = new IvParameterSpec(iv);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, COUNT, Integer.parseInt(attList.get(0)));

            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            SecretKeySpec key = new SecretKeySpec(pbeKey.getEncoded(), attList.get(1));

            cipher.init(Cipher.DECRYPT_MODE, key, ivv);

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
     * This method prints the files info
     * @param inputDir - Directory of the file
     */
    public void info(String inputDir) {
        for (String att : getAttributes(inputDir)) {
            System.out.println(att + " ");
        }
    }

    /***
     * This method is for getting the attributes of the given five
     * @param inputDir - The file we want to get the attributes from
     * @return - A list of attributes as strings
     */
    public List<String> getAttributes(String inputDir) {

        List<String> toReturn = new ArrayList<>();
        try {
            UserDefinedFileAttributeView fileAttributeView = Files.getFileAttributeView(Paths.get(inputDir), UserDefinedFileAttributeView.class);
            toReturn = fileAttributeView.list();
        } catch (IOException e) {
            System.out.println("Error reading meta data " + e.getMessage());
        }
        if (toReturn.size() != 2) {
            error("Incorrect number of attributes remove the existing file when encrypting");
        }
        return toReturn;
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