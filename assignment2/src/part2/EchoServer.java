package part2;

import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    private PrivateKey serverPrivateKey;
    private PublicKey serverPublicKey;
    private PublicKey clientPublicKey;

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
            serverPrivateKey = pkEntry.getPrivateKey();

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

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            keyStoreSetup();

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            Signature sig1 = Signature.getInstance("SHA256withRSA");
            byte[] data = new byte[512];
            int numBytes;


            //Use RSA/ECB/PKCS1Padding for the asymmetric encryption and SHA256withRSA for the signing
            final String cipherName = "RSA/ECB/PKCS1Padding";

            Cipher cipher = Cipher.getInstance(cipherName);

            while ((numBytes = in.read(data)) != -1) {

                byte[] signature = new byte[256];
                byte[] message = new byte[256];
                //Separate signature from message
                ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
                inputStream.read(signature);
                inputStream.read(message);

                //**************************************************************
                //**                       Decrypt                            **
                //**************************************************************

                cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                byte[] decryptedBytes = cipher.doFinal(message);
                String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

                //Print the received decrypted message
                System.out.println("Received: " + decryptedString);

                //Verify the message with the signature
                System.out.println("Checking signature...");
                sig1.initVerify(clientPublicKey);
                sig1.update(decryptedBytes);
                if (sig1.verify(signature)) {
                    System.out.println("Signature matches");
                } else {
                    throw new IllegalArgumentException("Signature does not match");
                }

                //**************************************************************
                //**                       Encrypt                            **
                //**************************************************************

                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);

                //convert message to bytes
                final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
                byte[] cipherTextBytes = cipher.doFinal(originalBytes);

                //Add the signature
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(serverPrivateKey);
                sig.update(originalBytes);
                byte[] signatureBytes = sig.sign();

                //Concatenate the signature and the message
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(signatureBytes);
                outputStream.write(cipherTextBytes);

                System.out.println("Sent: " + Util.bytesToHex(cipherTextBytes));
                out.write(outputStream.toByteArray());
                out.flush();
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } catch (Exception e) {
            handleExceptions(e);
        }
    }

    /**
     * Close the streams and sockets.
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) {
        EchoServer server = new EchoServer();
        server.start(4444);
    }

    public static void handleExceptions(Exception e) {
        System.out.println(e.getMessage());
    }
}



