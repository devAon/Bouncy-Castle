import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class CryptoHelper {

	private static CryptoHelper cryptoHelper = new CryptoHelper();

	public CryptoHelper() {

	}

	public static CryptoHelper getInstance() {
		return cryptoHelper;
	}

	private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}

	private KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Security.addProvider(new BouncyCastleProvider());
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
		SecureRandom random = new SecureRandom();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
		keyPairGenerator.initialize(ecSpec, random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public PrivateKey getPrivate(String filename, String cryptoType) throws Exception {
		// cryptoType {RSA, EC}
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(cryptoType);
		return kf.generatePrivate(spec);
	}

	public PublicKey getPublic(String filename, String cryptoType) throws Exception {
		// cryptoType {RSA, EC}
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance(cryptoType);
		return kf.generatePublic(spec);
	}

	public static byte[] sign(PrivateKey privateKey, byte[] ac) throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(privateKey);
		signature.update(ac);

		byte[] signatureData = signature.sign();
		return signatureData;
	}

	public static boolean isSigVal(PublicKey publicKey, byte[] signatureData, byte[] plainData)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}

	public static boolean isTicketVal(Map<String, Object> ticket, Map<String, Object> time) throws ParseException {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
		Date ticketTime = sdf.parse((String) ticket.get("timestamp"));
		Date timeFrom = sdf2.parse((String) time.get("from"));
		Date timeTo = sdf2.parse((String) time.get("to"));

		if (ticketTime.after(timeFrom) && ticketTime.before(timeTo)) {
			return true;
		}
		return false;
	}

	public PublicKey convertStringToPK(String cpk) throws NoSuchAlgorithmException, InvalidKeySpecException {
		cpk = cpk.replaceAll("-----BEGIN PUBLIC KEY-----", "");
		cpk = cpk.replaceAll("-----END PUBLIC KEY-----", "");
		cpk = cpk.replaceAll(System.getProperty("line.separator"), "");

		// CPK Base64 Decode
		byte[] decodedCpk = org.bouncycastle.util.encoders.Base64.decode(cpk);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedCpk);
		KeyFactory kf = KeyFactory.getInstance("EC");
		PublicKey cpkPublicKey = kf.generatePublic(spec);

		return cpkPublicKey;
	}


//    public static String bytesToHex(byte[] bytes) {
//        StringBuilder sb = new StringBuilder(bytes.length * 2);
//        @SuppressWarnings("resource")
//        Formatter formatter = new Formatter(sb);
//
//        for (byte b : bytes) {
//            formatter.format("%02x", b);
//        }
//        return sb.toString();
//    }

	// (1) Generate AC Signature using CS's ECDSA private key
	public byte[] SignAC(String ac) throws Exception {
		// String cryptoType =
		// GlobalConfig.getInstance().getCertConfig().getCryptoType();

		if (!new File("CS-KeyPair").exists())
			new File("CS-KeyPair").mkdir();
		if (!new File("CS-KeyPair/CS-PublicKey").exists() || !new File("CS-KeyPair/CS-PrivateKey").exists()) {
			KeyPair keyPair = null;
			keyPair = this.generateEcKeyPair();
			this.writeToFile(new File("CS-KeyPair/CS-PublicKey"), keyPair.getPublic().getEncoded());
			this.writeToFile(new File("CS-KeyPair/CS-PrivateKey"), keyPair.getPrivate().getEncoded());
		}

		PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", "EC");
		PrivateKey privateKey = this.getPrivate("CS-KeyPair/CS-PrivateKey", "EC");

		Charset charset = Charset.forName("UTF-8");
		byte[] signature = sign(privateKey, ac.getBytes(charset));

		// return bytesToHex(signature);
		return signature;
	}

	public byte[] getECPublicKey() throws Exception {
		PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", "EC");
		byte[] publicKeyBytes = publicKey.getEncoded();

		return publicKeyBytes;
	}

	public String EncryptRSA(String ac) throws Exception {
		// String cryptoType =
		// GlobalConfig.getInstance().getCertConfig().getCryptoType();
		Cipher cipher = Cipher.getInstance("RSA");

		if (!new File("CS-KeyPair").exists())
			new File("CS-KeyPair").mkdir();
		if (!new File("CS-KeyPair/CS-PublicKey").exists() || !new File("CS-KeyPair/CS-PrivateKey").exists()) {
			KeyPair keyPair = null;
			keyPair = this.generateRsaKeyPair();
			this.writeToFile(new File("CS-KeyPair/CS-PublicKey"), keyPair.getPublic().getEncoded());
			this.writeToFile(new File("CS-KeyPair/CS-PrivateKey"), keyPair.getPrivate().getEncoded());
		}

		PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", "RSA");
		PrivateKey privateKey = this.getPrivate("CS-KeyPair/CS-PrivateKey", "RSA");

		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		Base64.Encoder encoder = Base64.getEncoder();

		return encoder.encodeToString(cipher.doFinal(ac.getBytes("UTF-8")));
	}

	// SK cs-tgs 생성
	public SecretKey getSecretEncryptionKey() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES"); // AES Key Generator 객체 생성
		generator.init(128); // AES Key size 지정
		SecretKey secKey = generator.generateKey(); // AES 암호화 알고리즘에서 사용

		return secKey;
	}

	// CBC 암호화를 위해 IV 생성
	public IvParameterSpec getIvParameterSpec() throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] ivData = new byte[16]; // 128 bit
		random.nextBytes(ivData);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
		Charset charset = Charset.forName("UTF-8");

		return ivParameterSpec;
	}

	// CBC 운용모드 AES 암호화
	public byte[] encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, String plainData)
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
		byte[] encryptData = cipher.doFinal(plainData.getBytes());

		return encryptData;
	}

}
