import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    static HandshakeCertificate serverCert;
    static HandshakeCertificate caCert;
    static HandshakeCertificate clientCert;
    static HandshakeCrypto privateKey;
    static SessionKey sessionKey;
    static byte[] iv;
    static HandshakeMessage serverHello;
    static HandshakeMessage clientHello;
    static HandshakeMessage sessionMessage;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", " the name of a file with the server's certificate (in PEM format)");
        arguments.setArgumentSpec("cacert", "the name of a file with the certificate of the CA that (is supposed to have) signed the client's certificate (in PEM format)");
        arguments.setArgumentSpec("key", "the name of a file with the server's private key (in DER format).");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
        clientCert = loadCertificate(arguments.get("usercert"));
        caCert = loadCertificate(arguments.get("cacert"));
        privateKey = loadPrivateKey(arguments.get("key"));
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws Exception {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        sendClientHello(socket);
        checkServerHello(socket);
        handleSession(socket);
        checkServerFinished(socket);
        sendClientFinished(socket);
        try {
            SessionCipher sessionCipher = new SessionCipher(sessionKey, iv);
            OutputStream os = socket.getOutputStream();
            InputStream is = socket.getInputStream();
            CipherOutputStream cos = sessionCipher.openEncryptedOutputStream(os);
            CipherInputStream cis = sessionCipher.openDecryptedInputStream(is);
            Forwarder.forwardStreams(System.in, System.out, cis, cos, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
    private static HandshakeCertificate loadCertificate(String filePath) throws IOException, CertificateException {
        byte[] certBytes = Files.readAllBytes(Paths.get(filePath));
        return new HandshakeCertificate(certBytes);
    }
    private static HandshakeCrypto loadPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (filePath == null) {
            System.err.println("Private key path not provided.");
            System.exit(1);
        }
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get(filePath));
        return new HandshakeCrypto(privateKeyBytes);
    }
    private static void sendClientHello(Socket socket) throws IOException, CertificateEncodingException {
        // Send ClientHello
        clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        // Assume that the client certificate is encoded in Base64
        String clientCertBase64 = Base64.getEncoder().encodeToString(clientCert.getBytes());
        clientHello.putParameter("Certificate", clientCertBase64);
        clientHello.send(socket);
    }
    private static void checkServerHello(Socket socket) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        serverHello = HandshakeMessage.recv(socket);
        String serverCertBase64 = serverHello.getParameter("Certificate");
        byte[] serverCertBytes = Base64.getDecoder().decode(serverCertBase64);
        serverCert = new HandshakeCertificate(serverCertBytes);
        // Validate server certificate
        serverCert.verify(caCert);
        System.out.println("Server certificate validation successful.");
    }
    private static void handleSession(Socket socket) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        //Generate session key and IV
        sessionKey = new SessionKey(128);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        iv = sessionCipher.getIVBytes();

        //Encrypt session key and IV with server's public key
        HandshakeCrypto serverCrypto = new HandshakeCrypto(serverCert);
        byte[] encryptedSessionKey = serverCrypto.encrypt(sessionKey.getKeyBytes());
        byte[] encryptedIV = serverCrypto.encrypt(iv);

        sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKey));
        sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIV));
        sessionMessage.send(socket);
    }
    private static void sendClientFinished(Socket socket) throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {
        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        //Encrypt and send a digest of all previous messages with client's private key
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(clientHello.getBytes());
        digest.update(sessionMessage.getBytes());
        byte[] digestBytes = digest.digest();
        byte[] encryptedDigest = privateKey.encrypt(digestBytes);
        clientFinished.putParameter("Signature", Base64.getEncoder().encodeToString(encryptedDigest));

        //Encrypt and send current timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        byte[] encryptedTimestamp = privateKey.encrypt(timestamp.getBytes());
        clientFinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(encryptedTimestamp));
        clientFinished.send(socket);
    }

    private static void checkServerFinished(Socket socket) throws Exception {
        HandshakeMessage serverFinished = HandshakeMessage.recv(socket);
        //从ClientFinished消息中获取加密的签名和时间戳
        String encryptedSignatureBase64 = serverFinished.getParameter("Signature");
        String encryptedTimestampBase64 = serverFinished.getParameter("TimeStamp");

        //解密签名和时间戳
        HandshakeCrypto crypto = new HandshakeCrypto(serverCert);
        byte[] decryptedSignature = crypto.decrypt(Base64.getDecoder().decode(encryptedSignatureBase64));
        byte[] decryptedTimestamp = crypto.decrypt(Base64.getDecoder().decode(encryptedTimestampBase64));

        //验证签名
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(serverHello.getBytes());
        byte[] expectedSignature = digest.digest();

        if (!Arrays.equals(decryptedSignature, expectedSignature)) {
            System.out.println("Server signature validation failed.");
        }

        //验证时间戳
        String timestampString = new String(decryptedTimestamp, StandardCharsets.UTF_8);
        DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime timestamp = LocalDateTime.parse(timestampString, dateFormat);
        LocalDateTime localDateTime = LocalDateTime.now();

        long diff = Math.abs(Duration.between(timestamp, localDateTime).getSeconds());
        if(diff > 30){
            throw new Exception("timestamp different");
        }
        System.out.println("Clientfinished ok!");
    }
}
