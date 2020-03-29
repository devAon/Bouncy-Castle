import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BlockChainStarter {
	public static void main(String[] args) throws Exception {
		
		// 바운시 캐슬의 암호화 라이브러리 사용
		Security.addProvider(new BouncyCastleProvider());
		
		// 타원 곡선 객체 생성 개인키과 공개키를 각각 private.pem public.pem으로 저장
		EC ec = new EC();
		ec.generate("private.pem", "public.pem");
	}

}