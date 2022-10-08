package part2;

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private PrivateKey clientPrivateKey;
    private PublicKey clientPublicKey;
    private PublicKey serverPublicKey;

    /**
     * Setup the two way streams.
     *
     * @param ip   the address of the server
     * @param port port used by the server
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public byte[] sendMessage(byte[] msg) {
        try {
            //Send encrypted message
            out.write(msg);
            out.flush();

            //return reply to be decrypted
            byte[] reply = new byte[512];
            in.read(reply);
            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public void keyStoreSetup() throws IOException {
        FileInputStream fis = null;
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

            //Get password from user
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Password: ");
            char[] password = reader.readLine().toCharArray();

            fis = new java.io.FileInputStream("src/part2/cybr372.jks");
            ks.load(fis, password);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

            //Get private key from keystore
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                    ks.getEntry("cybr372", protParam);
            clientPrivateKey = pkEntry.getPrivateKey();

            //Get public key from certificate
            FileInputStream serverFin = new FileInputStream("src/part2/client.cer");
            CertificateFactory serverCert = CertificateFactory.getInstance("X.509");
            X509Certificate serverCertificate = (X509Certificate) serverCert.generateCertificate(serverFin);
            clientPublicKey = serverCertificate.getPublicKey();

            //Get public key from certificate
            FileInputStream clientFin = new FileInputStream("src/part2/server.cer");
            CertificateFactory clientCert = CertificateFactory.getInstance("X.509");
            X509Certificate clientCertificate = (X509Certificate) clientCert.generateCertificate(clientFin);
            serverPublicKey = clientCertificate.getPublicKey();

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    public void run(String ip, int port) {
        try {

            keyStoreSetup();

            //Message to be sent
            final String message = "CYBR372 Assignment 2";

            //Create the connection
            startConnection(ip, port);


            //**************************************************************
            //**                       Encrypt                            **
            //**************************************************************

            //Encrypt and sign message to the destination
            //Use RSA/ECB/PKCS1Padding for the asymmetric encryption and SHA256withRSA for the signing
            final String cipherName = "RSA/ECB/PKCS1Padding";

            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            //Convert message to bytes
            final byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] cipherTextBytes = cipher.doFinal(originalBytes);
            Signature sig = Signature.getInstance("SHA256withRSA");

            //Add the signature
            sig.initSign(clientPrivateKey);
            sig.update(originalBytes);
            byte[] signatureBytes = sig.sign();

            System.out.println("Sent: " + Util.bytesToHex(cipherTextBytes));

            //Concatenate the signature and the message
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(signatureBytes);
            outputStream.write(cipherTextBytes);

            //Send encrypted message and get reply
            byte[] reply = this.sendMessage(outputStream.toByteArray());


            //**************************************************************
            //**                       Decrypt                            **
            //**************************************************************

            byte[] signature = new byte[256];
            byte[] receivedMessage = new byte[256];
            //Separate signature from message
            ByteArrayInputStream inputStream = new ByteArrayInputStream(reply);
            inputStream.read(signature);
            inputStream.read(receivedMessage);

            cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
            byte[] decryptedBytes = cipher.doFinal(receivedMessage);
            String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

            //Print the received decrypted message
            System.out.println("Received: " + decryptedString);

            //Verify the message with the signature
            System.out.println("Checking signature...");
            sig.initVerify(serverPublicKey);
            sig.update(decryptedBytes);

            if (sig.verify(signature)) {
                System.out.println("Signature matches");
            } else {
                throw new IllegalArgumentException("Signature does not match");
            }
            this.stopConnection();
        } catch (Exception e) {
            handleExceptions(e);
        }
    }

    public static void main(String[] args) {
        EchoClient client = new EchoClient();
        client.run("127.0.0.1", 4444);

    }

    public static void handleExceptions(Exception e) {
        System.out.println("Error: " + e.getMessage());
    }
}
