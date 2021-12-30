package tool.encryptionAndDecryption;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.operator.OperatorCreationException;


import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.SymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.AsymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyPairTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyStoreTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PrivateKeyTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;

public class Test {
	public static void main(String[] args) throws Exception   {
		//init();
		decSM4();
	}
	public static void init() throws EncryptionAndDecryptionException, Exception {
		KeyPair k=KeyPairTool.generateGMKeyPair();
		Date begin=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-01-01 00:00:00");
		Date end=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2030-12-31 23:59:59");
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end, "C=CN , CN=GMTEST");
		System.out.println("GM-PUBLIC:"+Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo, k.getPublic()).getEncoded()));
		System.out.println("GM-PRIVATE:"+Base64.encodeBase64String(PrivateKeyTool.toEnvelopedKeyBlobByGMPrivateKey(k.getPrivate())));
	}
	
	public static void decSM4() throws Exception {
		String encBase64="zjuNhdXmOtfGO42/1X/3TUAPazVpotmdfVK+BDHqZ1hojZXL0bOjlhEJ823CLmvzsPaIj8aDGixty3akuR7q1e//17kbXlEhne/myptgHpANwW0lrsmXzLrkk7n+FADKOl+fRUdqow6A6cXHlZ1KIpD/0qjORn0aibI3IjSOif6bGWQHunSwbH0LhwyH4tXt";
		String encpwdbase64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALiISJlVPwS10AshwflIk0OkaiwZz6T6cqOCkaZMvvcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlZmNvv2x79R58Q19L9JLj2jm5Aq8r07UdtKJ0wRf4/269MrZOkuY9UzyuyZYtdRf8DkHA0bwKfPBE3uo4xhiKRAAAACwNh37/dYiEw+DX/NMoNPC";
		String privateKeyBase64="AQAAAAEEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAupu9OZBoT1d5i7fa3OE+m3/ECr5RIXjYZ8Ga5ntQkiAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN52lH/hbW8qIhoIPyCh3HvjRYm4gIR/hp0hhhXI4cDGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLG+/vCNOVxAlRVajMq+6sGWte34pYZIhYb3OM3F8GlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkhIsKgM/l251b7BkqaVcwzkuV/TeEJhTT0QYQ3sJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3pnWiuzZg5pzKXP3m3apoPfshkp6kkEmORMCU+PXFgFrJG3AFU8kfgf6EQSI62nzckMroROlb5Gvh1OrzFIbMQAAAAIkK2z/SKCY95yIahldKooQ==";
		byte [] enc=Base64.decodeBase64(encpwdbase64);
		enc=AsymmetricTool.GMC1C3C2TOSM2Cipher(enc);
		PrivateKey prk=PrivateKeyTool.toGMPrivateKeyByEnvelopedKeyBlob(Base64.decodeBase64(privateKeyBase64));
		byte[] pwd=	AsymmetricTool.decrypt(enc, prk, ProviderMode.Asymmetric.GM.Cipher.SM2);
		
		byte[] decFile=SymmetricTool.decrypt(Base64.decodeBase64(encBase64), pwd, lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_ECB_PKCS5Padding);
		
		String deviceCode= GAData.getObjFormAsn1(decFile).getDeviceCode();
		
		byte [] encDeviceCode=SymmetricTool.encrypt(deviceCode.getBytes("UTF-8"), pwd,  lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_ECB_PKCS5Padding);
		
		System.out.println("dataSymKeyEnc:"+encpwdbase64);
		System.out.println("encFile:"+encBase64);
		System.out.println("deviceCode:"+deviceCode);
		System.out.println("encDeviceCode:"+Base64.encodeBase64String(encDeviceCode));
		
	}
}
