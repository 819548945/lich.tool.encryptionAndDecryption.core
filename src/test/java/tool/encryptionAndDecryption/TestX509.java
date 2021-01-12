package tool.encryptionAndDecryption;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyPairTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;

public class TestX509 {
	public static void main(String[] args) throws OperatorCreationException, CertificateException, ParseException, IOException {
		new TestX509().test();
	}
	@Test
	public void test() throws OperatorCreationException, CertificateException, ParseException, IOException {
		System.out.println("--------------RSA--------------");
		testRsa();
		System.out.println("--------------GM--------------");
		testGM();
	}
	private void testRsa() throws ParseException, OperatorCreationException, CertificateException, IOException {
		KeyPair k=KeyPairTool.generateRSAKeyPair(1204);
		Date begin=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-01-01 00:00:00");
		Date end=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-12-31 23:59:59");
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end, "C=CN , CN=RSATEST");
		System.out.println("RSA:"+Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo, k.getPublic()).getEncoded()));	
	}
	private void testGM() throws ParseException, OperatorCreationException, CertificateException, IOException {
		KeyPair k=KeyPairTool.generateGMKeyPair();
		Date begin=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-01-01 00:00:00");
		Date end=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-12-31 23:59:59");
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end, "C=CN , CN=GMTEST");
		System.out.println("GM:"+Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo, k.getPublic()).getEncoded()));	
	}
}
