package lich.tool.encryptionAndDecryption.ext;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Hex;

import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.SymmetricTool;
public class DefaultSM4Ext implements SM4Ext{
	/**
	 * SM4加密
	 * @param in 原文
	 * @param keyBytes 密钥
	 * @return 加密数据
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	  public  byte[] encrypt(byte[] in, byte[] keyBytes) throws Exception {
		  byte[] b1;
		  if(in.length%32!=0&&in[0]==0x00) {
			  b1=new byte[in.length-1];
			  System.arraycopy(in, 1, b1, 0, in.length-1);
		  }else b1=in;
		  return  SymmetricTool.encrypt(b1, keyBytes, ProviderMode.Symmetric.Cipher.SM4_ECB_NOPadding);
	  }
	  /**
	   * SM4解密
	   * @param in 密文
	   * @param keyBytes 密钥
	   * @return 姐猕猴数据
	
	   */
	  public  byte[] decrypt(byte[] in, byte[] keyBytes) throws Exception {
		  return  SymmetricTool.decrypt(in, keyBytes, ProviderMode.Symmetric.Cipher.SM4_ECB_NOPadding);
	  }
}
