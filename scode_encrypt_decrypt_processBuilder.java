import java.io.IOException;
public class scode_encrypt_decrypt_processBuilder {
  public static void main(String[] args) {
    String publicKeyPath = "/path/to/public_key.pem";
    String privateKeyPath = "/path/to/private_key.pem";
    String inputFile = "/path/to/te.txt";
    String encryptedFile = "/path/to/encrypted.bin";
    String decryptedFile = "/path/to/decrypted.txt";
    // Encrypt the file
    encryptFile(publicKeyPath, inputFile, encryptedFile);
    // Decrypt the file
    decryptFile(privateKeyPath, encryptedFile, decryptedFile);
  }

  private static void encryptFile(String publicKeyPath, String inputFile, String encryptedFile) {
    try {
      ProcessBuilder processBuilder = new ProcessBuilder("openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", publicKeyPath, "-in", inputFile, "-out", encryptedFile);
      Process process = processBuilder.start();
      int exitCode = process.waitFor();
      if (exitCode == 0) {
        System.out.println("File encrypted successfully.");
      } else {
        System.err.println("Encryption failed. Exit code: " + exitCode);
      }
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
    }
  }

  private static void decryptFile(String privateKeyPath, String encryptedFile, String decryptedFile) {
    try {
      ProcessBuilder processBuilder = new ProcessBuilder("openssl", "pkeyutl", "-decrypt", "-inkey", privateKeyPath, "-in", encryptedFile, "-out", decryptedFile);
      Process process = processBuilder.start();
      int exitCode = process.waitFor();
      if (exitCode == 0) {
        System.out.println("File decrypted successfully.");
      } else {
        System.err.println("Decryption failed. Exit code: " + exitCode);
      }
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
    }
  }
}