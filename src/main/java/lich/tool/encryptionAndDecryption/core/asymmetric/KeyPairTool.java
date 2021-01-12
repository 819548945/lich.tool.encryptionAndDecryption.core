package lich.tool.encryptionAndDecryption.core.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.Base;

/**
 * 密钥对生成工具
 * @author liuch
 *
 */
public class KeyPairTool extends Base{
	
    private KeyPairTool() {}
	/**
	 * SM2密钥对生成
	 * @return SM2密钥对
	 */
	public static KeyPair generateGMKeyPair() {
		try {
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC, BC);
			kpGen.initialize(ecParameterSpec, new SecureRandom());
			KeyPair kp = kpGen.generateKeyPair();
			return kp;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	/**
	 * RSA密钥对生成
	 * @param keySize 密钥长度
	 * @return RSA密钥对
	 */
	public static  KeyPair generateRSAKeyPair(int keySize) {
		try {
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA, BC);
			kpGen.initialize(keySize, new SecureRandom());
			KeyPair kp = kpGen.generateKeyPair();
			return kp;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	
}
