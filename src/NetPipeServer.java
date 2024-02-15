import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
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
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", " the name of a file with the server's certificate (in PEM format)");
        arguments.setArgumentSpec("cacert", "the name of a file with the certificate of the CA that (is supposed to have) signed the client's certificate (in PEM format)");
        arguments.setArgumentSpec("key", "the name of a file with the server's private key (in DER format).");
        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }

        //加载服务器证书,CA证书，私钥
        serverCert = loadCertificate(arguments.get("usercert"));
        caCert = loadCertificate(arguments.get("cacert"));
        privateKey = loadPrivateKey(arguments.get("key"));
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws Exception {
        parseArgs(args);
        ServerSocket serverSocket = null;
        int port = Integer.parseInt(arguments.get("port"));


        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        checkClientHello(socket);
        sendServerHello(socket);
        handleSession(socket);
        sendServerFinished(socket);
        checkClientFinished(socket);
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

    /* Handshake protocol:
    1. accept ClientHello and respond ServerHello;
    2. receive session key and IV, decrypt from server's private key
    3. send digest and timestamp, encrypt with server's private key
    4. receive digest and timestamp and verify
     */

    private static void checkClientHello(Socket socket) throws Exception {
        clientHello = HandshakeMessage.recv(socket);
        //接收客户端证书
        String clientCertBase64 = clientHello.getParameter("Certificate");
        byte[] clientCertBytes = Base64.getDecoder().decode(clientCertBase64);
        clientCert = new HandshakeCertificate(clientCertBytes);
        //验证客户端证书
        clientCert.verify(caCert);
        System.out.println("Client Certification Verification successful!");
    }
    private static void sendServerHello(Socket socket) throws CertificateEncodingException, IOException {
        //把服务器证书发送给客户端
        serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        byte[] serverCertEncoded = serverCert.getBytes();
        serverHello.putParameter("Certificate", Base64.getEncoder().encodeToString(serverCertEncoded));
        serverHello.send(socket);
    }

    private static void handleSession(Socket socket) throws Exception {
        sessionMessage = HandshakeMessage.recv(socket);
        //解密会话密钥和 IV
        String encryptedSessionKeyBase64 = sessionMessage.getParameter("SessionKey");
        String encryptedIVBase64 = sessionMessage.getParameter("SessionIV");
        byte[] sessionKeyBytes = privateKey.decrypt(Base64.getDecoder().decode(encryptedSessionKeyBase64));

        iv = privateKey.decrypt(Base64.getDecoder().decode(encryptedIVBase64));
        sessionKey = new SessionKey(sessionKeyBytes);
    }
    private static void sendServerFinished(Socket socket) throws Exception {
        //计算哈希值
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(serverHello.getBytes());
        byte[] serverHelloHash = digest.digest();
        //加密哈希值
        byte[] encryptedHash = privateKey.encrypt(serverHelloHash);
        String signatureBase64 = Base64.getEncoder().encodeToString(encryptedHash);
        //获取当前当前时间戳并加密
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        byte[] encryptedTimestamp = privateKey.encrypt(timestamp.getBytes(StandardCharsets.UTF_8));
        String encryptedTimestampBase64 = Base64.getEncoder().encodeToString(encryptedTimestamp);
        //创建并发送ServerFinished消息
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        serverFinished.putParameter("Signature", signatureBase64);
        serverFinished.putParameter("TimeStamp", encryptedTimestampBase64);
        serverFinished.send(socket);
    }

    private static void checkClientFinished(Socket socket) throws Exception {
        HandshakeMessage clientFinished = HandshakeMessage.recv(socket);
        //从ClientFinished消息中获取加密的签名和时间戳
        String encryptedSignatureBase64 = clientFinished.getParameter("Signature");
        String encryptedTimestampBase64 = clientFinished.getParameter("TimeStamp");

        //解密签名和时间戳
        HandshakeCrypto crypto = new HandshakeCrypto(clientCert);
        byte[] decryptedSignature = crypto.decrypt(Base64.getDecoder().decode(encryptedSignatureBase64));
        byte[] decryptedTimestamp = crypto.decrypt(Base64.getDecoder().decode(encryptedTimestampBase64));

        //验证签名
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(clientHello.getBytes());
        digest.update(sessionMessage.getBytes());
        byte[] expectedSignature = digest.digest();

        if (!Arrays.equals(decryptedSignature, expectedSignature)) {
            System.out.println("Client signature validation failed.");
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
