import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class EC {
	// 세부 알고리즘 sect163k1
	private final String ALGORITHM = "sect163k1";
	
	public void generate(String privateKeyName, String publicKeyName) throws Exception {
		// ECDSA(bouncy castle의 타원 곡선 표준 알고리즘) 사용
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
		
		// 세부 알고리즘 sect163k1
		ECGenParameterSpec ecsp;
		ecsp = new ECGenParameterSpec(ALGORITHM);
		generator.initialize(ecsp, new SecureRandom());
		
		// 해당 알고리즘으로 랜덤의 키 한 쌍 생성
		KeyPair keyPair = generator.generateKeyPair();
		System.out.println("타원곡선 암호키 한 쌍을 생성했씁니다아앙.");
		
		// 생성한 키 한쌍에서 개인키와 공개키를 추출
		PrivateKey priv = keyPair.getPrivate();
		PublicKey pub = keyPair.getPublic();
		
		// 개인키와 공개키를 특정한 파일 이름으로 저장
		writePemFile(priv, "EC PRIVATE KEY", privateKeyName);
		writePemFile(pub, "EC PUBLIC KEY", publicKeyName);
		
	}

	// PEM 클래스로 생성된 암호키를 파일로 저장하는 함수
	private void writePemFile(Key key, String description, String filename) 
				throws FileNotFoundException, IOException {
		Pem pemFile = new Pem(key, description);
		pemFile.write(filename);
		
		System.out.println(String.format("EC 암호키 %s를 %s 파일로 내보냈습니당.", 
				description, filename));
	}

}