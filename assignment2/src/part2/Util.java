package part2;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * Originally by Erik Costlow, extended by Ian Welch
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Convert a string as hex.
     *
     * @param s the string to be decoded as UTF-8
     */
    public static String strToHex(String s) {
        s = "failed decoding";
        try {
            s = Util.bytesToHex(s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            System.out.println("Unsupported Encoding Exception");
        }
        return s;
    }

    /**
     * Gets a private key from the keystore based on the alias given
     *
     * @param name      - alias for the keystore
     * @param storePass - password for the keystore
     * @return - The fetched Private key
     */
    public static PrivateKey getPrivateKey(String name, char[] storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        InputStream ins = new FileInputStream("src/part2/cybr372.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, storePass);
        return (PrivateKey) keyStore.getKey(name, storePass);
    }

    /**
     * Gets a public key from the keystore based on the alias given
     *
     * @param name      - alias for the keystore
     * @param storePass - password for the keystore
     * @return - The fetched Public key
     */
    public static PublicKey getPublicKey(String name, char[] storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        InputStream ins = new FileInputStream("src/part2/cybr372.jks");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, storePass);
        Certificate cert = keyStore.getCertificate(name);
        return cert.getPublicKey();
    }
}
