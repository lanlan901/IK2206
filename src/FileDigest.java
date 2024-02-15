import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class FileDigest {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java FileDigest <filename>");
            System.exit(1);
        }

        String filename = args[0];
        try {
            // Read file and compute its hash
            HandshakeDigest digest = new HandshakeDigest();
            byte[] fileBytes = readFileBytes(filename);
            digest.update(fileBytes);
            byte[] hashBytes = digest.digest();

            // Encode hash as Base64 and print
            String base64Hash = Base64.getEncoder().encodeToString(hashBytes);
            System.out.println(base64Hash);
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static byte[] readFileBytes(String filename) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(filename);
        byte[] fileBytes = fileInputStream.readAllBytes();
        fileInputStream.close();
        return fileBytes;
    }
}