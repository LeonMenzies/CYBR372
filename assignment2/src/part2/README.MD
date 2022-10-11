# Part 2

# Part 3

### Instructions

The following commands are used to generate the keystore with a certificates for the alias "server" and "client"

- keytool -genkeypair -alias server -keyalg rsa -storepass badpassword -keystore cybr372.jks -storetype PKCS12 -dname "
  CN=ROOT"
- keytool -genkeypair -alias client -keyalg rsa -storepass badpassword -keystore cybr372.jks -storetype PKCS12 -dname "
  CN=ROOT"


1. Run the EchoServer
2. enter the password "badpassword"
3. Run the EchoClient
4. enter the password "badpassword"
7. The program will run and the outputs will be shown

### Testing

Client running
![](../../../../../../../../../var/folders/n3/c9_flf894f74bq7xj750jhxw0000gn/T/TemporaryItems/NSIRD_screencaptureui_MW6hxj/Screen Shot 2022-10-11 at 7.38.22 PM.png)

server running
![](../../../../../../../../../var/folders/n3/c9_flf894f74bq7xj750jhxw0000gn/T/TemporaryItems/NSIRD_screencaptureui_PP2Tf6/Screen Shot 2022-10-11 at 7.38.38 PM.png)

The process for part 2 is teh same as part 1 except this time te initial inputs are the password to the keystore and not
the key directly. The rest of teh functionality acts the same using teh same string "CYBR372 Assignment 2".

### Design choices

I created two methods in the Util class, one for getting the private key and one for getting the public key. now instead
of using the keys generated in the program the client or server calls the required method to get access to the necessary
key for either encryption or decryption.