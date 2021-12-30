package tool.encryptionAndDecryption;


import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.Base;
import lich.tool.encryptionAndDecryption.core.asymmetric.AsymmetricTool;

public class TestSM2Transformation {
	public static void main(String[] args) throws Exception {
		new TestSM2Transformation().test();
	}
	@Test
	public void test() throws Exception {
		byte[] ori="测试1111".getBytes("utf-8");
		
		System.out.println("-----------不转换测试-----------");
		byte[]  sign= AsymmetricTool.sign(ori, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2);
		//sign= AsymmetricTool.sign(ori.getBytes("utf-8"), privateKey, Provider.RSA.Signature.SHA256WithRSA);
		System.out.println("sign:"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori, Base.getRootGMX509Certificate().getPublicKey(),ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2));
		byte [] enc=AsymmetricTool.encrypt(ori, Base.getRootGMX509Certificate().getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println("enc:"+Base64.encodeBase64String(enc));
		System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
		System.out.println("-----------转换测试-----------");
		sign=AsymmetricTool.SM2SignatureToRS(sign);
		System.out.println("sign(RS):"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori, Base.getRootGMX509Certificate().getPublicKey(),ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2));
		sign=AsymmetricTool.RSToSM2Signature(sign);
		System.out.println("sign(RS->SM2Signature):"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori,Base.getRootGMX509Certificate().getPublicKey(),ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2));
		enc=AsymmetricTool.SM2CipherToSM2EncDataC1C2C3(enc);
		System.out.println("enc(C1C2C3):"+Base64.encodeBase64String(enc));
		//System.out.println("ori(c1c2c3):"+new String(AsymmetricTool.decrypt(enc, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
		enc=AsymmetricTool.SM2EncDataC1C2C3ToSM2Cipher(enc);
		System.out.println("enc(C1C2C3->SM2Cipher):"+Base64.encodeBase64String(enc));
		//System.out.println("ori(c1c2c3->SM2Cipher):"+new String(AsymmetricTool.decrypt(enc, Base.getRootGMPrivateKey(), ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
		String s1=Base64.encodeBase64String(AsymmetricTool.SM2CipherTOGMC1C3C2(enc));
		System.out.println("SM2Cipher->GMC1C3C2):"+s1);
		s1=Base64.encodeBase64String(AsymmetricTool.GMC1C3C2TOSM2Cipher(Base64.decodeBase64(s1)));
		System.out.println("GMC1C3C2->SM2Cipher):"+s1);
	}
}
