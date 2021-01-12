package tool.encryptionAndDecryption;


import java.security.PrivateKey;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.Base;
import lich.tool.encryptionAndDecryption.core.asymmetric.AsymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PrivateKeyTool;

public class TestSM2PrivateIO {
	public static void main(String[] args) throws Exception {
		new TestSM2PrivateIO().test();
	}
	@Test
	public void test() throws Exception {
		byte[] ori="测试1111".getBytes("utf-8");
		System.out.println("-----------测试原密钥正确性-----------");
		byte[]  sign= AsymmetricTool.sign(ori, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2);
		System.out.println("sign:"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori, Base.getRootGMX509Certificate().getPublicKey(),ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2));
		byte [] enc=AsymmetricTool.encrypt(ori,  Base.getRootGMX509Certificate().getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println("enc:"+Base64.encodeBase64String(enc));
		System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
		System.out.println("-----------测试导出密钥-----------");
		byte [] envelopedKeyBlob=	PrivateKeyTool.toEnvelopedKeyBlobByGMPrivateKey(PrivateKeyTool.getRootGMPrivateKey());
		System.out.println("envelopedKeyBlob:"+Base64.encodeBase64String(envelopedKeyBlob));
		PrivateKey npk=PrivateKeyTool.toGMPrivateKeyByEnvelopedKeyBlob(envelopedKeyBlob);
		sign= AsymmetricTool.sign(ori, npk, ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2);
		System.out.println("sign:"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori,Base.getRootGMX509Certificate().getPublicKey(),ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2));
		enc=AsymmetricTool.encrypt(ori,  Base.getRootGMX509Certificate().getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println("enc:"+Base64.encodeBase64String(enc));
		System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, npk, ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
	}
}
