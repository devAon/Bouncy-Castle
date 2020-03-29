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
	// ���� �˰��� sect163k1
	private final String ALGORITHM = "sect163k1";
	
	public void generate(String privateKeyName, String publicKeyName) throws Exception {
		// ECDSA(bouncy castle�� Ÿ�� � ǥ�� �˰���) ���
		KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA", "BC");
		
		// ���� �˰��� sect163k1
		ECGenParameterSpec ecsp;
		ecsp = new ECGenParameterSpec(ALGORITHM);
		generator.initialize(ecsp, new SecureRandom());
		
		// �ش� �˰������� ������ Ű �� �� ����
		KeyPair keyPair = generator.generateKeyPair();
		System.out.println("Ÿ��� ��ȣŰ �� ���� �����߾��ϴپƾ�.");
		
		// ������ Ű �ѽֿ��� ����Ű�� ����Ű�� ����
		PrivateKey priv = keyPair.getPrivate();
		PublicKey pub = keyPair.getPublic();
		
		// ����Ű�� ����Ű�� Ư���� ���� �̸����� ����
		writePemFile(priv, "EC PRIVATE KEY", privateKeyName);
		writePemFile(pub, "EC PUBLIC KEY", publicKeyName);
		
	}

	// PEM Ŭ������ ������ ��ȣŰ�� ���Ϸ� �����ϴ� �Լ�
	private void writePemFile(Key key, String description, String filename) 
				throws FileNotFoundException, IOException {
		Pem pemFile = new Pem(key, description);
		pemFile.write(filename);
		
		System.out.println(String.format("EC ��ȣŰ %s�� %s ���Ϸ� �����½��ϴ�.", 
				description, filename));
	}

}