package part1;

import javax.crypto.Cipher;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
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
     *
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

    public void run(String ip, int port){
        try {
            //Message to be sent
            final String message = "CYBR372 Assignment 2";

            //Create the connection
            EchoClient client = new EchoClient();
            client.startConnection(ip, port);

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

            //**************************************************************
            //**                       Encrypt                            **
            //**************************************************************

            //Encrypt and sign message to the destination
            //Use RSA/ECB/PKCS1Padding for the asymmetric encryption and SHA256withRSA for the signing
            final String cipherName = "RSA/ECB/PKCS1Padding";

            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.ENCRYPT_MODE, destinationPublicKey);

            //Convert message to bytes
            final byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] cipherTextBytes = cipher.doFinal(originalBytes);
            Signature sig = Signature.getInstance("SHA256withRSA");

            //Add the signature
            sig.initSign(privateKey);
            sig.update(originalBytes);
            byte[] signatureBytes = sig.sign();

            System.out.println("Sent: "+ Util.bytesToHex(cipherTextBytes));

            //Concatenate the signature and the message
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(signatureBytes);
            outputStream.write(cipherTextBytes);

            //Send encrypted message and get reply
            byte[] reply = client.sendMessage(outputStream.toByteArray());


            //**************************************************************
            //**                       Decrypt                            **
            //**************************************************************

            byte[] signature = new byte[256];
            byte[] receivedMessage  = new byte[256];
            //Separate signature from message
            ByteArrayInputStream inputStream = new ByteArrayInputStream(reply);
            inputStream.read(signature);
            inputStream.read(receivedMessage);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(receivedMessage);
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
            client.stopConnection();
        } catch (Exception e){
            handleExceptions(e);
        }
    }

    public static void main(String[] args)  {
       EchoClient client = new EchoClient();
       client.run("127.0.0.1", 4444);
    }

    public static void handleExceptions(Exception e) {
        System.out.println("Error: " + e.getMessage());
    }
}
