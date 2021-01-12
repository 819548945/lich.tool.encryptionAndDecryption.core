package lich.tool.encryptionAndDecryption.core;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * 对称加解密工具类
 * @author liuch
 *
 */
public class SymmetricTool extends Base{
	/**
	 * 对称加密
	 * @param ori 原文
	 * @param pwd 密码
	 * @param algorithm 加密算法
	 * @return 加密数据
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte [] ori,byte [] pwd,lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c=Cipher.getInstance(algorithm.getAlgorithm(), BC);
		SecretKey key=new SecretKeySpec(pwd, algorithm.getKeyType());
    	c.init(Cipher.ENCRYPT_MODE, key);
		return c.doFinal(ori);
	}
	/**
	 * 对称解密
	 * @param enc 加密数据
	 * @param pwd 密码
	 * @param algorithm 加密算法
	 * @return 加密数据
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte [] enc,byte [] pwd,lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher c=Cipher.getInstance(algorithm.getAlgorithm(), BC);
		SecretKey key=new SecretKeySpec(pwd, algorithm.getKeyType());
    	c.init(Cipher.DECRYPT_MODE, key,new SecureRandom());
		return c.doFinal(enc);
	}
	/**
	 * 
	 * 对称加密
	 * @param ori 原文
	 * @param pwd 密码
	 * @param algorithm 加密算法
	 * @param iv 向量
	 * @return 加密数据
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] encrypt(byte [] ori,byte [] pwd,lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher algorithm,byte [] iv) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher c=Cipher.getInstance(algorithm.getAlgorithm(), BC);
		SecretKey key=new SecretKeySpec(pwd, algorithm.getKeyType());
    	c.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(iv));
		return c.doFinal(ori);
	}
	/**
	 * 对称解密
	 * @param enc 加密数据
	 * @param pwd 密码
	 * @param algorithm 加密算法
	 * @param iv 向量
	 * @return 解密数据
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] decrypt(byte [] enc,byte [] pwd,lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher algorithm,byte [] iv) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher c=Cipher.getInstance(algorithm.getAlgorithm(), BC);
		SecretKey key=new SecretKeySpec(pwd, algorithm.getKeyType());
    	c.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));
		return c.doFinal(enc);
	}
}
