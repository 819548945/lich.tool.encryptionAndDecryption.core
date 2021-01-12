package tool.encryptionAndDecryption;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.core.SymmetricTool;
import lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher;



public class TestSymmetric {
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		new TestSymmetric().test();
	}
	@Test
	public void test() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		byte[] pwd=new byte[8];
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_ECB_NOPadding);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_ECB_PKCS5Padding);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_ECB_PKCS7Padding);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_ECB_PKCS7Padding);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_ECB_PKCS5Padding);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_ECB_NOPadding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_CBC_NOPadding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_CBC_PKCS5Padding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.SM4_CBC_PKCS7Padding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_CBC_PKCS7Padding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_CBC_PKCS5Padding);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.AES_CBC_NOPadding);
		
		
		new SecureRandom().nextBytes(pwd);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_ECB_PKCS7Padding,pwd);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_ECB_PKCS5Padding,pwd);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_ECB_NOPadding,pwd);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_CBC_PKCS7Padding,pwd);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_CBC_PKCS5Padding,pwd);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DES_CBC_NOPadding,pwd);
		pwd=new byte[16];
		new SecureRandom().nextBytes(pwd);
		byte [] iv=new byte[8];
		new SecureRandom().nextBytes(iv);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_ECB_PKCS7Padding,pwd);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_ECB_PKCS5Padding,pwd);
		testEcb(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_ECB_NOPadding,pwd);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_CBC_PKCS7Padding,pwd,iv);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_CBC_PKCS5Padding,pwd,iv);
		testCbc(lich.tool.encryptionAndDecryption.ProviderMode.Symmetric.Cipher.DESede_CBC_NOPadding,pwd,iv);
		
		
	}
	public void testEcb(Cipher c,byte ... pw) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println( "----------test:"+c+"---------------");
		if(pw.length==0)pw="1234567812345678".getBytes();
		String ori="1111111111111111";
		System.out.println("ori:"+ori);
		byte[] enc=SymmetricTool.encrypt(ori.getBytes(), pw, c);
		System.out.println("enc:"+Hex.encodeHexString(enc));
		byte[] dec=SymmetricTool.decrypt(enc, pw,c);
		System.out.println("dec:"+new String(dec));
		System.out.println( "----------test:"+c+" OK---------------");
		
	}
	public void testCbc(Cipher c,byte ... pw) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		byte[] b= {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
		System.out.println( "----------test:"+c+"---------------");
		if(pw.length==0) pw="1234567812345678".getBytes();
		else b=pw;
		String ori="1111111111111111";
		System.out.println("ori:"+ori);
		byte[] enc=SymmetricTool.encrypt(ori.getBytes(), pw, c,b);
		System.out.println("enc:"+Hex.encodeHexString(enc));
		byte[] dec=SymmetricTool.decrypt(enc, pw,c,b);
		System.out.println("dec:"+new String(dec));
		System.out.println( "----------test:"+c+" OK---------------");
		
	}
	public void testCbc(Cipher c,byte[] pw,byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		System.out.println( "----------test1:"+c+"---------------");
		String ori="1111111111111111";
		System.out.println("ori:"+ori);
		byte[] enc=SymmetricTool.encrypt(ori.getBytes(), pw, c,iv);
		System.out.println("enc:"+Hex.encodeHexString(enc));
		byte[] dec=SymmetricTool.decrypt(enc, pw,c,iv);
		System.out.println("dec:"+new String(dec));
		System.out.println( "----------test:"+c+" OK---------------");
		
	}
}
