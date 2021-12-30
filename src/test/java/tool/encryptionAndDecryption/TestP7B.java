package tool.encryptionAndDecryption;


import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;

import org.junit.Test;

import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyPairTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;

public class TestP7B {
	public static void main(String[] args) throws Exception {
		new TestP7B().test();
	}
	@Test
	public void test() throws Exception {
		Date begin=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-01-01 00:00:00");
		Date end=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-12-31 23:59:59");
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end, "C=CN , CN=GMTEST");
		System.out.println("-----------certificateChainToP7b-----------");
		X509Certificate x509c=PublicKeyTool.getX509Certificate(publicKeyInfo, KeyPairTool.generateGMKeyPair().getPublic())	;
		X509Certificate chain []= {PublicKeyTool.getRootGMX509Certificate(),x509c};
		String p7b=Base64.encodeBase64String(PublicKeyTool.certificateChainToP7b(chain, true));
		System.out.println("p7b:"+p7b);
		byte [][] chain1= {PublicKeyTool.getRootGMX509Certificate().getEncoded(),x509c.getEncoded()};
		p7b=Base64.encodeBase64String(PublicKeyTool.certificateChainToP7b(chain1, true));
		System.out.println("p7b1:"+p7b);
		System.out.println("-----------loadP7bToChain-----------");
		X509Certificate[] xx=	PublicKeyTool.loadP7bToChain(Base64.decodeBase64(p7b),true);
		for(X509Certificate x:xx) {
			System.out.println(x.getSubjectDN().toString());
		}
		System.out.println("-----------loadP7bToX509Certificate-----------");
		X509Certificate x=	PublicKeyTool.loadP7bToX509Certificate(Base64.decodeBase64(p7b),true);
		System.out.println(x.getSubjectDN().toString());
	}
}
