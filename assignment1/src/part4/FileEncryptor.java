package part4;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
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
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";
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
            if (args.length != 6) {
                error("Invalid number of inputs");
            }

            String algorithm = "AES";
            int keyLength = 256;

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
            } else if (Objects.equals(args[1], "Blowfish")) {
                try {
                    keyLength = Integer.parseInt(args[2]);

                    if (!(keyLength >= 32 && keyLength <= 448)) {
                        error("Invalid key length, must be 128, 192, or 256");
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

                if (keyLength % 8 != 0) {
                    error("Invalid key length, must be dividable by 8");
                }

            } catch (NumberFormatException nfe) {
                error("Key length must be a number");
            }

            //Generate the IV
            SecureRandom sr = new SecureRandom();
            byte[] initVector = new byte[16];
            sr.nextBytes(initVector);

            enc(algorithm, keyLength, args[3].toCharArray(), initVector, args[4], args[5]);
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
     * @param initVector - The initial vector for encrypting the file
     * @param inputDir - The path to the file that is being encrypted
     * @param outputDir - The path where the encrypted file will be save
     * @throws Exception - Exceptions thrown by internal methods
     */
    public void enc(String algorithm, int keyLength, char[] password, byte[] initVector, String inputDir, String outputDir) throws Exception {

        // Salt
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] secret = generateKey(password, salt, keyLength, algorithm).getEncoded();

        System.out.println("Secret key is " + bytesToHex(secret).replaceAll("\\s+", ""));

        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(secret, algorithm);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

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

            //Write meta data to file attributes
            UserDefinedFileAttributeView userDefinedFAView = Files.getFileAttributeView(Paths.get(outputDir), UserDefinedFileAttributeView.class);
            //Write the key to the file meta-data
            userDefinedFAView.write(keyLength + "", Charset.defaultCharset().encode(keyLength + ""));
            //Write the algorithm type to the file meta-data
            userDefinedFAView.write(algorithm, Charset.defaultCharset().encode(algorithm));


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

            //Get the attributes needed to create the key and decrypt the data
            List<String> attList = getAttributes(inputDir);

            IvParameterSpec iv = new IvParameterSpec(ivs);

            SecretKeySpec skeySpec = new SecretKeySpec(generateKey(password, salt, Integer.parseInt(attList.get(0)), attList.get(1)).getEncoded(), attList.get(1));
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);


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

    public void info(String inputDir) {
        for (String att : getAttributes(inputDir)) {
            System.out.println(att + " ");
        }
    }

    public List<String> getAttributes(String inputDir) {

        List<String> toReturn = new ArrayList<>();
        try {
            UserDefinedFileAttributeView fileAttributeView = Files.getFileAttributeView(Paths.get(inputDir), UserDefinedFileAttributeView.class);
            toReturn = fileAttributeView.list();
        } catch (IOException e) {
            System.out.println("Error reading meta data " + e.getMessage());
        }
        if (toReturn.size() != 2) {
            error("No attributes found");
        }
        return toReturn;
    }

    public SecretKey generateKey(char[] password, byte[] salt, int keyLength, String algorithm) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, COUNT, keyLength);

        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
    }

    public void error(String message) {
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