# Part 2

### Certificate commands

Generate keystore

- keytool -genkeypair -alias server -keyalg rsa -storepass badpassword -keystore cybr372.jks -storetype PKCS12 -dname "
  CN=ROOT"
- keytool -genkeypair -alias client -keyalg rsa -storepass badpassword -keystore cybr372.jks -storetype PKCS12 -dname "
  CN=ROOT"

Generate certificates

- keytool -genkey -alias client -keyalg RSA -keystore cybr372.jks -storepass <password>  -storetype JKS
- keytool -genkey -alias server -keyalg RSA -keystore cybr372.jks -storepass <password>  -storetype JKS