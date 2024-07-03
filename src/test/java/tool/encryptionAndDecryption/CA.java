package tool.encryptionAndDecryption;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.SymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyPairTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PrivateKeyTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;


public class CA {
	public static void main(String[] args) throws EncryptionAndDecryptionException, Exception {
	/*	byte [] bc=SymmetricTool.decrypt(org.bouncycastle.util.encoders.Base64.decode("RaNnnNqK4GfGg8MTzYDEjjPzPGbWtLNi6balGNcBj8A="), org.bouncycastle.util.encoders.Base64.decode("CsjRu4G/ItJyQXXtJfBUyA=="), ProviderMode.Symmetric.Cipher.SM4_ECB_NOPadding);
		System.out.println(Hex.encodeHexString(bc));
		System.out.println(bc.length);*/
		

	
		
	
		Date begin=new Date(((long)1680248498)*1000);
		Date end=	new Date(((long)1711870898)*1000);
		String dn= "C=CN,O="+"test"+",CN="+"test11";
		String key="BCxaVdhSoflz/NzZKqws3UVZeNU0eN/06HRK3xPGM5w+2IpjUdgjQ+sq7EyYzbDFg/Q8O300aw0AOOg13AS2AqE=";
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end,dn);
	//	String signSn=Hex.encodeHex(publicKeyInfo.getSerial().toByteArray());
		PublicKey spuk=	PublicKeyTool.toGMPublicKey(Base64.decodeBase64(key));
		String scert=	Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo,spuk ).getEncoded());
		KeyPair kp=	KeyPairTool.generateGMKeyPair();
		publicKeyInfo.setSerial(BigInteger.valueOf(System.currentTimeMillis()));
		String ecert=   Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo,kp.getPublic() ).getEncoded());
		String eprk=	Base64.encodeBase64String(PrivateKeyTool.toEnvelopedKeyBlobByGMPrivateKey(kp.getPrivate(),spuk));
		String epuk=	Base64.encodeBase64String(PublicKeyTool.getPublicKeyByte(kp.getPublic()))	;
		System.out.println("enccert:"+ecert);
		System.out.println("encprk:"+eprk);
		System.out.println("signcert:"+scert);
		System.out.println(Hex.encodeHexString(Base64.decodeBase64(key)));
	
		;
		System.out.println(Hex.encodeHexString(PublicKeyTool.getPublicKeyByte(PublicKeyTool.loadX509Certificate(Base64.decodeBase64(scert)).getPublicKey())));
	}
}
