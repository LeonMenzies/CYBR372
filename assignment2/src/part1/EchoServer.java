package part1;

import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private Signature sig;

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            sig = Signature.getInstance("SHA256withRSA");
            byte[] data = new byte[512];
            int numBytes;

            //Generate public and private key pairs programmatically
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            final KeyPair kp = kpg.generateKeyPair();

            final PublicKey publicKey = kp.getPublic();
            final PrivateKey privateKey = kp.getPrivate();

            //Print out the public key on the console in base 64
            System.out.println("Public key:");
            System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            //Allow user to enter the public key for the destination
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Destination public key: ");
            String destinationPublicKeyString = reader.readLine();

            //Convert string to PublicKey Object
            byte[] destinationPublicKeyBytes = Base64.getDecoder().decode(destinationPublicKeyString);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey destinationPublicKey = factory.generatePublic(new X509EncodedKeySpec(destinationPublicKeyBytes));

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

                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decryptedBytes = cipher.doFinal(message);
                String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

                //Print the received decrypted message
                System.out.println("Received: "+ decryptedString);

                //Verify the message with the signature
                System.out.println("Checking signature...");
                sig.initVerify(destinationPublicKey);
                sig.update(decryptedBytes);
                if (sig.verify(signature)) {
                    System.out.println("Signature matches");
                } else {
                    throw new IllegalArgumentException("Signature does not match");
                }

                //**************************************************************
                //**                       Encrypt                            **
                //**************************************************************
                
                cipher.init(Cipher.ENCRYPT_MODE, destinationPublicKey);

                //convert message to bytes
                final byte[] originalBytes = decryptedString.getBytes(StandardCharsets.UTF_8);
                byte[] cipherTextBytes = cipher.doFinal(originalBytes);

                //Add the signature
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(privateKey);
                sig.update(originalBytes);
                byte[] signatureBytes = sig.sign();

                //Concatenate the signature and the message
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(signatureBytes);
                outputStream.write(cipherTextBytes);

                System.out.println("Sent: "+ Util.bytesToHex(cipherTextBytes));
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
     *
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



