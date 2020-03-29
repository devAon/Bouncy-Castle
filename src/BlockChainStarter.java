import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BlockChainStarter {
	public static void main(String[] args) throws Exception {
		
		// �ٿ�� ĳ���� ��ȣȭ ���̺귯�� ���
		Security.addProvider(new BouncyCastleProvider());
		
		// Ÿ�� � ��ü ���� ����Ű�� ����Ű�� ���� private.pem public.pem���� ����
		EC ec = new EC();
		ec.generate("private.pem", "public.pem");
	}

}