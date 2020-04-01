[
고려대 프로젝트 암호화 - 공개키, 비밀키, Bouncy Castle, 프로젝트개요, CryptoHelper 코드](https://aonee.tistory.com/manage/newpost/37?type=post&returnURL=https%3A%2F%2Faonee.tistory.com%2Fentry%2F%25EA%25B3%25A0%25EB%25A0%25A4%25EB%258C%2580-%25ED%2594%2584%25EB%25A1%259C%25EC%25A0%259D%25ED%258A%25B8-%25EC%2595%2594%25ED%2598%25B8%25ED%2599%2594)


### **🔥목차*🔥***

***🍓* 1. 공개키(=비대칭키) - RSA, ECDSA**

***🍓* 2. 비밀키(=대칭키) -AES**

***🍓* 3. Bouncy Castle, 인증서**

***🍓* 4. 프로젝트 개요**

***🍓* 5. CS 개발에 필요한 CryptoHelper 코드**
        
         
           
          
           
           
### ***🍓 1.* 공개키(=비대칭키) - RSA, ECDSA**

공개키, 개인키

**공개키** : **전송자**가 정보 **암호화**하는데 사용**

**개인키** : **수신자**가 암호 **해독**에 사용

누구나 암호화는 가능하다. 그러나 개인키를 가진 사람만 해독이 가능하다.



![img](https://k.kakaocdn.net/dn/cBaD66/btqC7rG0ptI/7BjvjJtCqWxfqx6YkkyPbk/img.png)

**RSA : 암호화, 전자서명**

**ECDSA** : Elliptic Curve Digital Signature Algorithm (기본 서명, 암호화)

**ECIES** : Elliptic Curve Integrated Encryption scheme (공유 대칭키 생성)





**( 관련 포스팅 )**
[
공개키 암호 시스템, 개인키 암호 시스템공개키 (= 비대칭키)](https://aonee.tistory.com/entry/공개키-암호-시스템-개인키-암호-시스템)








### ***🍓 2.* 비밀키(=대칭키) - AES**

암호화와 복호화에 같은 암호키를 쓰는 알고리즘을 의미한다.

![img](https://k.kakaocdn.net/dn/bOcjnW/btqC8HJj01G/bMQYpBBhfOGBe1hd6iO2Gk/img.png)



**장점**

1. 키 크기가 상대적으로 작고 암호 알고리즘 내부 구조가 단순하다.

2. 시스템 개발 환경에 용이하다.

3. 비대칭키에 비해 암호화와 복호화 속도가 빠르다



**단점**

1. 교환 당사자간에 동일한 키를 공유해야 하기 때문에 키관리의 어려움이 있고

2. 잦은 키 변경이 있는 경우에 불편함을 초래한다. 

3. 디지털 서명 기법에 적용이 곤란하고 안전성을 분석하기가 어렵고 중재자가 필요하다.



### ***🍓 3.*  Bouncy Castle, 인증서\*\*\*\*\*\**\***

**Bouncy Castle 이란?**

자바암호라이브러리이다.

Java에서 타원 곡선 암호화 기술을 쉽게 이용 가능하도록 해준다.



**eclipse 에서 library 추가 방법**

1. widow - preferences - Java - Build Path - User Libraries

  여기서 New - library명 내가 원하는대로 적고 ok - apply and close

2. project 우클릭 - build path - add libraries - User Library - 내가 만든 라이브러리 선택 - Finish





**intellij 에서 \**library 추가 방법\****

```
<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on -->
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcpkix-jdk15on</artifactId>
            <version>1.60</version>
        </dependency>
```





**인증서 란?** 

컴퓨터에 저장된 개인키/공개키 파일

- 일반적으로 인증서 정보는 byte 형태로 저장되어있어 읽거나 처리가 어려우므로 키 데이터를 Base64 알고리즘을 이용해 사용하기 쉬운 형태로 인코딩 해서 관리함
- PEM(Privacy Enhanced Mail) : 인코딩된 파일 .pem 확장자



### **🍓 4. 프로젝트 개요** 



![img](https://k.kakaocdn.net/dn/ceEJgN/btqC781tlvn/YGqlNs2bcoK1kNjRryLBL0/img.png)



**cdm 공통데이터 모델 :** 진료기록을 동일한 포맷으로 통일하여 연구에 활용.

**개발 목표 :** 보안적으로 안전한 cdm 데이터 분석 플랫폼 설계 및 개발

**WI :** 클라이언트 프로그램.

**AS** : 로그인용.

**CS** : 분석코드 & 무결성 보장 전자서명 준비

**TGS** : 티켓준비.

**RS :** 준비된 [분석코드. 전자서명. 티켓] 을 SS에 전달.



**시나리오**

\1. 중간에 연구망서버를 두고 연구망서버에 여러 대학병원들의 서버가 연결된다.

\2. CDM데이터를 분석하고 싶은 연구자가 연구망서버에 분석을 하기 위한 소스코드를 전달하면

  연구망서버가 다시 연결되어 있는 각 대학병원의 서버쪽으로 분석코드를 쭉 분해를 한다.

\3. 대학병원에 있는 서버는 분석코드를 받아 실행을 하고 분석된 결과를

   다시 연구망서버로 회신해주면

   연구자가 연구망서버에 모여있는 분석결과를 가져가는 방식이다.



### ***🍓 5.* CS 개발에 필요한 CryptoHelper 코드**

**CS (Code Signer) : 분석코드 & 무결성 보장 전자서명 준비**

분석코드를 연구자가 연구망서버로 업로드를 하는데,

그 분석코드가 네트워크를 타고 다시 대학병원에 전달된다.

이때 중간에 데이터 변조가 일어나지 않도록 (=데이터 무결성을 지킬 수 있도록)

전자서명을 추가해주는 역할을 한다.



![img](https://k.kakaocdn.net/dn/bW0UVV/btqC491rYNr/Gk6FCeMw0yr5qZe4PR3900/img.png)

**✔ (3) C -> CS : 검증을 위한 복호화**


**① Sig2C 검증** 
\- signature, cpk 이용해서 발신인이 C라는 것을 확인 
\- http://www.bitweb.co.kr/m/view.php?idx=921 
 

 **① -1) Client로부터 PK+ 획득** 
  \- Base64 Decoding : 공개키를 Base64 Decoding
  \- Decoding한 PK+(공개키)를 다시 Public Key 형태로 변경

 **① -2) Signature Base64 Decoding**

  \- Signature 획득 
  \- Signature를 Base64 Decoding 
  \- JSON Body 자체를 toString()화 해서

  \- verify(cpkPublicKey, decodedSignature, Body); 수행
    Jackson 라이브러리 사용     

```
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.8.8</version>
</dependency>
```



 **① -3) ECDSA PK+(Signature)** 


**② sk 복호화** 
\- 현재는 없기 때문에 SKIP 

**③ 티켓 복호화** 
\- ticket 
 \- cname 
 \- institution 
 \- time 
  \- from 
  \- to 
\1. 티켓의 유효기간 확인 
\2. 티켓의 cname, institution 확인







**✔ (4) CS -> C : 검증을 위한 복호화**


**① TGS 티켓 발행**

  **① - 1)** Sk를 생성한다 (비밀키 생성) 
  **① - 2)** Sk로 IDc, Hospitalc, Time 정보를 암호화한다 
  **① - 3)** 암호화된 텍스틀를 보낸다 



**② CS ECDSA 서명**

  **② - 1)** TGS공개키를 생성한다 
  **② - 2)** (SK CS-TGS) 정보를 암호화한다



**③ AC \**ECDSA 서명\****

**④ C에게 전달할 메시지 JSON**



**(cryptoHelper 전체코드)**

https://github.com/devAon/BouncyCastle/blob/master/src/CryptoHelper.java

[
devAon/BouncyCastleBouncy Castle Crypto APIs. Contribute to devAon/BouncyCastle development by creating an account on GitHub.github.com](https://github.com/devAon/BouncyCastle/blob/master/src/CryptoHelper.java)

**RSA**

```
private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }
```



**ECDSA**

```
private KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(ecSpec, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
```



**키생성 후 파일 저장**

```
private void writeToFile(File output, byte[] toWrite)
        throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }
```



**getPrivate**

```
 public PrivateKey getPrivate(String filename, String cryptoType) throws Exception {
        // cryptoType {RSA, EC}
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(cryptoType);
        return kf.generatePrivate(spec);
    }
```



**getPublic**

```
public PublicKey getPublic(String filename, String cryptoType) throws Exception {
        // cryptoType {RSA, EC}
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(cryptoType);
        return kf.generatePublic(spec);
    }
```



**getPrivate, getPublic 사용**

```
if (!new File("CS-KeyPair/CS-PublicKey").exists() || !new File("CS-KeyPair/CS-PrivateKey").exists()) {
            KeyPair keyPair = null;
            keyPair = this.generateEcKeyPair();
            this.writeToFile(new File("CS-KeyPair/CS-PublicKey"), keyPair.getPublic().getEncoded());
            this.writeToFile(new File("CS-KeyPair/CS-PrivateKey"), keyPair.getPrivate().getEncoded());
        }
        
PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", "EC");
PrivateKey privateKey = this.getPrivate("CS-KeyPair/CS-PrivateKey", "EC");
```



**sign 전자서명**

```
public static byte[] sign(PrivateKey privateKey, byte[] ac) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(ac);

        byte[] signatureData = signature.sign();
        return signatureData;
    }
```



**SignAC** : Generate AC Signature using CS's ECDSA private key

```
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
```



**getECPublicKey**

```
public byte[] getECPublicKey() throws Exception {
		PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", "EC");
		byte[] publicKeyBytes = publicKey.getEncoded();

		return publicKeyBytes;
	}
```





**EncryptRSA**

```
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
```



**SK cs-tgs 생성**

```
public SecretKey getSecretEncryptionKey() throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("AES"); // AES Key Generator 객체 생성
		generator.init(128); // AES Key size 지정
		SecretKey secKey = generator.generateKey(); // AES 암호화 알고리즘에서 사용

		return secKey;
	}
```



**CBC 암호화를 위해 IV 생성**

```
public IvParameterSpec getIvParameterSpec() throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] ivData = new byte[16]; // 128 bit
		random.nextBytes(ivData);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivData);
		Charset charset = Charset.forName("UTF-8");

		return ivParameterSpec;
	}
```



**CBC 운용모드 AES 암호화**

```
public byte[] encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec, String plainData)
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
		byte[] encryptData = cipher.doFinal(plainData.getBytes());

		return encryptData;
	}
```



**isSigVal** : 전자서명 검증

```
public static boolean isSigVal(PublicKey publicKey, byte[] signatureData, byte[] plainData)
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}
```





**isTicketVal** : 티켓 검증

```
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
```







**convertStringToPK** : String dmf Public Key로 변환

```
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
```
