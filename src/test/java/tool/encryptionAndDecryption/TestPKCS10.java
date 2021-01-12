package tool.encryptionAndDecryption;


import java.security.KeyPair;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyPairTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyStoreTool;

public class TestPKCS10 {
	
	public static void main(String[] args) throws Exception {
		new TestPKCS10().testGMP10();
	}
	@Test
	public void testRSAP10() throws Exception {
		KeyPair k=KeyPairTool.generateRSAKeyPair(1204);
		byte[] b=KeyStoreTool.toPKCS10(k, "C=CN,O=lich", ProviderMode.Asymmetric.RSA.Signature.SHA1WithRSA);
		System.out.println("RSAP10:"+Base64.encodeBase64String(b));
	}
	@Test
	public void testGMP10() throws Exception {
		KeyPair k=KeyPairTool.generateGMKeyPair();
		byte[] b=KeyStoreTool.toPKCS10(k, "C=CN,O=lich", ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2);
		System.out.println("GMP10:"+Base64.encodeBase64String(b));	
	}
}
