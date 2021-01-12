package tool.encryptionAndDecryption;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.DigestTool;

public class TestMessageDigest {
	public static void main(String[] args) throws Exception {
		new TestMessageDigest().test1();
	}
	@Test
	public void test1() throws Exception {
		this.test(ProviderMode.MessageDigest.MD2);
		this.test(ProviderMode.MessageDigest.MD4);
		this.test(ProviderMode.MessageDigest.MD5);
		this.test(ProviderMode.MessageDigest.SHA1);
		this.test(ProviderMode.MessageDigest.SHA224);
		this.test(ProviderMode.MessageDigest.SHA256);
		this.test(ProviderMode.MessageDigest.SHA384);
		this.test(ProviderMode.MessageDigest.SHA512);
		this.test(ProviderMode.MessageDigest.SHA3_224);
		this.test(ProviderMode.MessageDigest.SHA3_256);
		this.test(ProviderMode.MessageDigest.SHA3_384);
		this.test(ProviderMode.MessageDigest.SHA3_512);
		this.test(ProviderMode.MessageDigest.SM3);
	}
	public void test(String algorithm) throws Exception {
		byte [] ori="测试原文".getBytes("utf-8");
		System.out.println("-----------"+algorithm+"------------");
		byte [] digest=DigestTool.getDigest(ori, algorithm);
		System.out.println(Base64.encodeBase64String(digest));
	}
}
