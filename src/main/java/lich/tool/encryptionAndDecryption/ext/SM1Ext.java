package lich.tool.encryptionAndDecryption.ext;


/**
 * SM1扩展接口
 * @author liuch
 *
 */
public interface SM1Ext {
	/**
	 * SM1加密
	 * @param in 原文
	 * @param keyBytes 密钥
	 * @return 加密数据
	 */
	  public byte[] encrypt(byte[] in, byte[] keyBytes) throws Exception;
	  /**
	   * SM1解密
	   * @param in 密文
	   * @param keyBytes 密钥
	   * @return 姐猕猴数据
	   */
	  public  byte[] decrypt(byte[] in, byte[] keyBytes) throws Exception;
}
