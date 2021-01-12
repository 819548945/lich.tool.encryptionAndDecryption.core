package lich.tool.encryptionAndDecryption.core;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 摘要工具类
 * @author liuch
 *
 */
public class DigestTool extends Base{
	/**
	 * 获取摘要
	 * @param ori 原文
	 * @param algorithm 摘要算法
	 * @return 摘要
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] getDigest(byte [] ori,String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		MessageDigest messageDigest = MessageDigest.getInstance(algorithm,BC);
		return messageDigest.digest(ori);
	}
}
