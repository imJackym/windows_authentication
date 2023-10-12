import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class scode_key_generate_encryption_decryption {
  private static final String PUBLIC_KEY_PATH = "public_key.pem";
  private static final String PRIVATE_KEY_PATH = "private_key.pem";
  private static final String PASSWORD_FILE_PATH = "pw.txt";
  private static final String ENCRYPTED_FILE_PATH = "encrypted_pw.txt";
  private static final String DECRYPTED_FILE_PATH = "decrypted_pw.txt";

  public static void main(String[] args) {
    try {
      // Generate public-private key pair
      KeyPair keyPair = generateKeyPair();

      // Save the keys to files
      savePublicKey(keyPair.getPublic(), PUBLIC_KEY_PATH);
      savePrivateKey(keyPair.getPrivate(), PRIVATE_KEY_PATH);

      // Read the password file
      String password = readPasswordFile(PASSWORD_FILE_PATH);
      System.out.println("password: " + password);

      // Encrypt the password
      byte[] encryptedPassword = encryptPassword(password, keyPair.getPublic());

      // Save the encrypted password to a file
      saveEncryptedPasswordToFile(encryptedPassword, ENCRYPTED_FILE_PATH);

      // Decrypt the password
      byte[] encryptedPasswordFromFile = readEncryptedPasswordFromFile(ENCRYPTED_FILE_PATH);
      String decryptedPassword = decryptPassword(encryptedPasswordFromFile, keyPair.getPrivate());

      // Save the decrypted password to a file
      saveDecryptedPasswordToFile(decryptedPassword, DECRYPTED_FILE_PATH);

      System.out.println("Password encryption and decryption completed successfully! " );
      System.out.println("decryptedPassword: " + decryptedPassword);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static KeyPair generateKeyPair() 
    throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private static void savePublicKey(PublicKey publicKey, String publicKeyPath) 
    throws IOException {
    byte[] publicKeyBytes = publicKey.getEncoded();
    X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
    Files.write(Paths.get(publicKeyPath), spec.getEncoded());
  }

  private static void savePrivateKey(PrivateKey privateKey, String privateKeyPath) 
    throws IOException {
    byte[] privateKeyBytes = privateKey.getEncoded();
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
    Files.write(Paths.get(privateKeyPath), spec.getEncoded());
  }

  private static String readPasswordFile(String passwordFilePath) throws IOException {
    return new String(Files.readAllBytes(Paths.get(passwordFilePath)));
  }

  private static byte[] encryptPassword(String password, PublicKey publicKey) 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return cipher.doFinal(password.getBytes());
  }

  private static void saveEncryptedPasswordToFile(byte[] encryptedPassword, String encryptedFilePath) 
    throws IOException {
    Files.write(Paths.get(encryptedFilePath), encryptedPassword);
  }

  private static byte[] readEncryptedPasswordFromFile(String encryptedFilePath) 
    throws IOException {
    return Files.readAllBytes(Paths.get(encryptedFilePath));
  }

  private static String decryptPassword(byte[] encryptedPassword, PrivateKey privateKey) 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decryptedPasswordBytes = cipher.doFinal(encryptedPassword);
    return new String(decryptedPasswordBytes);
  }

  private static void saveDecryptedPasswordToFile(String decryptedPassword, String decryptedFilePath) 
    throws IOException {
    try (FileWriter writer = new FileWriter(decryptedFilePath)) {
        writer.write(decryptedPassword);
    }
  }
}