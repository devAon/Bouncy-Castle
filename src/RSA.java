import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key; 
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSA {

	public static final int KEY_SIZE = 1024;
	
	public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException{
		// TODO Auto-generated method stub
		
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BC");
		generator.initialize(KEY_SIZE);
		
		KeyPair keyPair = generator.generateKeyPair();
		System.out.println("RSA 키 쌍을 생성했습니다.");
		
		RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
		
		writePemFile(priv, "RSA PRIVATE KEY", "private.pem");
		writePemFile(pub, "RSA PUBLIC KEY", "public.pem");
		
	}
	
	private static void writePemFile(Key key, String description, String filename)
								throws FileNotFoundException, IOException{
		Pem pemFile = new Pem(key, description);
		pemFile.write(filename);
		
		System.out.println(String.format("%s를  %s 파일로 내보냈습니다.", description, filename));
		
		
		
	}

}
