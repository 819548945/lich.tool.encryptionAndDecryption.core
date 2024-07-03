package lich.tool.encryptionAndDecryption.core.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;


import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.Base;

/**
 * 非对称加解密工具类
 * @author liuch
 *
 */
public class AsymmetricTool extends Base{
	private static SM2ParameterSpec parameterSpec = new SM2ParameterSpec("1234567812345678".getBytes());
	/**
	 * 公钥加密
	 * GM模式 加密数据结构为SM2Cipher der格式
	 * @param data 待加密数据
	 * @param publicKey 公钥
	 * @param algorithm  摘要算法
	 * @return 加密数据
	 * @throws EncryptionAndDecryptionException 
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws IllegalBlockSizeException 
	 * @throws BadPaddingException 
	 * @throws IOException 
	 */
	public static byte [] encrypt(byte[] data, PublicKey publicKey,String algorithm) throws EncryptionAndDecryptionException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		Cipher cipher =null;
    	if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.GM.Cipher.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持"+algorithm+" encrypt");
    		}
    		cipher = Cipher.getInstance(algorithm, BC);
    		
    	}else if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.RSA.Cipher.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持"+algorithm+" encrypt");
    		}
    		cipher = Cipher.getInstance(algorithm, BC);
    	}else {
    		throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持的密钥类型");
    	}
    	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    	if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC))return SM2EncDataC1C2C3ToSM2Cipher(cipher.doFinal(data));
    	else  return cipher.doFinal(data);
    }
	/**
	 * 私钥解密
	 * GM模式 加密数据结构为C1C2C3 或SM2Cipher der格式
	 * @param encodedataByte 加密数据
	 * @param privateKey 私钥
	 * @param algorithm 摘要算法
	 * @return 解密数据
	 * @throws InvalidCipherTextException
	 * @throws EncryptionAndDecryptionException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException 
	 */
    public static byte [] decrypt(byte[]  encodedataByte, PrivateKey privateKey,String algorithm) throws InvalidCipherTextException, EncryptionAndDecryptionException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException{
    	Cipher cipher =null;
    	if(privateKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.GM.Cipher.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持"+algorithm+" decrypt");
    		}
    		cipher = Cipher.getInstance(algorithm, BC);
    		encodedataByte=SM2CipherToSM2EncDataC1C2C3(encodedataByte);
    	}else if(privateKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.RSA.Cipher.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持"+algorithm+" decrypt");
    		}
    		cipher = Cipher.getInstance(algorithm, BC);
    	}else {
    		throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持的密钥类型");
    	}
    	cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encodedataByte);
    }
    /**
     * 签名
     * @param ori 原文
     * @param privateKey 私钥
     * @param algorithm 摘要算法
     * @return 签名值
     * @throws CryptoException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws EncryptionAndDecryptionException 
     */
    public static byte [] sign(byte[] ori, PrivateKey privateKey,String algorithm) throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, EncryptionAndDecryptionException {
    	
    	Signature signer =null;
    	if(privateKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
    		if("1.2.156.10197.1.501".equals(algorithm)) {
        		algorithm=ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2;
        	}
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.GM.Signature.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持"+algorithm+" sign");
    		}
    		signer = Signature.getInstance(algorithm, BC);
    		signer.setParameter(parameterSpec);
    	}else if(privateKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.RSA.Signature.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持"+algorithm+" sign");
    		}
    		signer = Signature.getInstance(algorithm, BC);
    	}else {
    		throw new EncryptionAndDecryptionException(privateKey.getAlgorithm()+"不支持的密钥类型");
    	}
        signer.initSign(privateKey, new SecureRandom());
        signer.update(ori, 0, ori.length);
        byte[] sig = signer.sign();
        return sig;
    }
    /**
     * 签名
     * @param ori 原文
     * @param privateKey 私钥
     * @param cert 公钥证书
     * @return 签名值
     * @throws EncryptionAndDecryptionException 
     * @throws CryptoException 
     * @throws SignatureException 
     * @throws InvalidAlgorithmParameterException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public static byte [] sign(byte[] ori, PrivateKey privateKey,X509Certificate cert) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, CryptoException, EncryptionAndDecryptionException {
    	return sign( ori, privateKey,cert.getSigAlgName()); 
    }
   
   /**
    * 验签
    * @param sign 签名值
    * @param ori 原文
    * @param publicKey 公钥
    * @param algorithm 摘要算法
    * @return true false
    * @throws NoSuchAlgorithmException
    * @throws NoSuchProviderException
    * @throws InvalidAlgorithmParameterException
    * @throws InvalidKeyException
    * @throws SignatureException
    * @throws EncryptionAndDecryptionException 
    * @throws IOException 
    */
    public static boolean verify(byte[] sign,byte[] ori, PublicKey publicKey,String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, EncryptionAndDecryptionException, IOException {
    	
    	Signature verifier=null;
    	if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
    		if("1.2.156.10197.1.501".equals(algorithm)) {
        		algorithm=ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2;
        	}
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.GM.Signature.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持"+algorithm+" verify");
    		}
    		verifier = Signature.getInstance(algorithm, BC);
            verifier.setParameter(parameterSpec);
            sign=sign.length<67?RSToSM2Signature(sign):RSToSM2Signature(SM2SignatureToRS(sign));
    	}else if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
    		if(!ProviderMode.Check.contains(ProviderMode.Asymmetric.RSA.Signature.class, algorithm)) {
    			throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持"+algorithm+" verify");
    		}
    		verifier = Signature.getInstance(algorithm, BC);
    	}else {
    		throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持的密钥类型");
    	}
    	verifier.initVerify(publicKey);
        verifier.update(ori, 0, ori.length);
        return verifier.verify(sign);
    }
    /** 
     * 验签
     * @param sign 签名值
     * @param ori 原文
     * @param cert 公钥证书
     * @return true false
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws SignatureException
     * @throws EncryptionAndDecryptionException
     * @throws IOException 
     */
    public static boolean verify(byte[] sign,byte[] ori,X509Certificate cert) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, EncryptionAndDecryptionException, IOException {
    	return verify(sign,ori, cert.getPublicKey(),cert.getSigAlgName());
    }
    
    
   /* /**
	 * SM2加密数据格式转换 
	 * @param b SM2Cipher
	 * @return 国密C1C2C3
	 * @throws IOException
	 */
    /*public static byte[]  SM2CipherTOGMC1C2C3(byte[] b) throws IOException{
    	DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
		byte[] enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();
		int enclen=(enc[0]==0x0)?enc.length-1:enc.length;
		byte[] encData=new byte[enclen+64*2+32+4];
		System.arraycopy(x, x[0]==0x0?1:0, encData, 64-(x[0]==0x0?x.length-1:x.length), 64);
		System.arraycopy(y, y[0]==0x0?1:0, encData, 128-(y[0]==0x0?y.length-1:y.length),64);
		encData[128]=0x10;
		System.arraycopy(enc,0, encData, 129,enclen);
		System.arraycopy(hash,0, encData, encData.length-32,32);
		return encData;
    }*/
  /*  /**
	 * SM2加密数据格式转换 
	 * @param b C1C2C3
	 * @return SM2Cipher
	 * @throws IOException
	 */
	/*public static byte[] GMC1C2C3ToSM2Cipher(byte[] b) throws IOException {	
		int keylen=b[0]*8;
		byte[] x=new byte[keylen];
		byte[] y=new byte[keylen];
		byte[] hash	=new byte[32];
		byte[] enc	=new byte[b.length-keylen*2-32-1];		
		System.arraycopy(b, 1, x, 0, 32);
		System.arraycopy(b, 33, y, 0, 32);
		System.arraycopy(b, 65, enc, 0, enc.length);
		System.arraycopy(b, 65+enc.length, hash, 0, 32);
		ASN1EncodableVector	sm2enc=new ASN1EncodableVector();
		sm2enc.add(new ASN1Integer(new BigInteger(1,x)));
		sm2enc.add(new ASN1Integer(new BigInteger(1,y)));
		sm2enc.add(new DEROctetString(hash));
		sm2enc.add(new DEROctetString(enc));
		return new DERSequence(sm2enc).getEncoded();
	}*/
    public static byte[] SM2CipherToEncDataC1C3C2(byte[] b) throws IOException {	
		DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
		byte[] enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();
		int enclen=(enc[0]==0x0)?enc.length-1:enc.length;
		int keylen=	x.length/8;
		byte[] encData=new byte[enclen+1+keylen*8*2+32];
		encData[0]=(byte)keylen;
		System.arraycopy(x, x[0]==0x0?1:0, encData, 1, keylen*8);
		System.arraycopy(y, y[0]==0x0?1:0, encData, keylen*8+1, keylen*8);
		System.arraycopy(hash,0, encData, 2*keylen*8+1,32);
		System.arraycopy(enc,0, encData, 2*keylen*8+1+32,enclen);	
		return encData;
	}
    /**
   	 * SM2加密数据格式转换 
   	 * @param b SM2Cipher
   	 * @return 国密C1C3C2
   	 * @throws IOException
   	 */
     public static byte[]  SM2CipherTOGMC1C3C2(byte[] b) throws IOException{
       	DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
   		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
   		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
   		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
   		byte[] enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();
   		int enclen=(enc[0]==0x0)?enc.length-1:enc.length;
   		byte[] encData=new byte[enclen+64*2+32+4];
   		System.arraycopy(x, x[0]==0x0?1:0, encData, 64-(x[0]==0x0?x.length-1:x.length),x[0]==0x0?x.length-1:x.length );
   		System.arraycopy(y, y[0]==0x0?1:0, encData, 128-(y[0]==0x0?y.length-1:y.length),x[0]==0x0?x.length-1:x.length);
   		System.arraycopy(hash,0, encData, 128,32);
   		encData[160]=(byte) (enclen&0xff);
   		encData[161]=(byte) (enclen>>8&0xff);
   		encData[162]=(byte) (enclen>>16&0xff);
   		encData[163]=(byte) (enclen>>24&0xff);
   		System.arraycopy(enc,0, encData, 164,enclen);
   		return encData;
     }
     /**
    	 * SM2加密数据格式转换 
    	 * @param b 国密C1C3C2
    	 * @return SM2Cipher
    	 * @throws IOException
    	 */
     public static byte[]   GMC1C3C2TOSM2Cipher(byte[] b) throws IOException{
		byte[] x=new byte[64];
		byte[] y=new byte[64];
		byte[] hash	=new byte[32];
		byte[] enc	=new byte[b.length-64*2-32-4];		
		System.arraycopy(b, 0, x, 0, 64);
		System.arraycopy(b, 64, y, 0, 64);
		System.arraycopy(b, 128, hash, 0,32);
		System.arraycopy(b, 128+32+4, enc, 0, b.length-128-32-4);
		ASN1EncodableVector	sm2enc=new ASN1EncodableVector();
		sm2enc.add(new ASN1Integer(new BigInteger(1,x)));
		sm2enc.add(new ASN1Integer(new BigInteger(1,y)));
		sm2enc.add(new DEROctetString(hash));
		sm2enc.add(new DEROctetString(enc));
		return new DERSequence(sm2enc).getEncoded();
    	
     }
    
     /**
	 * SM2加密数据格式转换 
	 * @param b SM2Cipher
	 * @return C1C2C3
	 * @throws IOException
	 */
	public static byte[] SM2CipherToSM2EncDataC1C2C3(byte[] b) throws IOException {	
		DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
		byte[] enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();
		int enclen=(enc[0]==0x0)?enc.length-1:enc.length;
		int keylen=	x.length/8;
		byte[] encData=new byte[enclen+1+keylen*8*2+32];
		encData[0]=(byte)keylen;
		System.arraycopy(x, x[0]==0x0?1:0, encData, 1, keylen*8);
		System.arraycopy(y, y[0]==0x0?1:0, encData, keylen*8+1, keylen*8);
		System.arraycopy(enc,0, encData, keylen*8*2+1,enclen);
		System.arraycopy(hash,0, encData, encData.length-32,32);
		return encData;
	}
	  /**
		 * SM2加密数据格式转换 
		 * @param b SM2Cipher
		 * @return C1C3C2
		 * @throws IOException
		 */
	public static byte[] SM2CipherToSM2EncDataC1C3C2(byte[] b) throws IOException {	
		DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
		byte[] enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();
		int enclen=(enc[0]==0x0)?enc.length-1:enc.length;
		int keylen=	x.length/8;
		byte[] encData=new byte[enclen+1+keylen*8*2+32];
		encData[0]=(byte)keylen;
		System.arraycopy(x, x[0]==0x0?1:0, encData, 1, keylen*8);
		System.arraycopy(y, y[0]==0x0?1:0, encData, keylen*8+1, keylen*8);
		System.arraycopy(hash,0, encData, 2*keylen*8+1,32);
		System.arraycopy(enc,0, encData, 2*keylen*8+1+32,enclen);	
		return encData;
	}
	
	/**
	 * SM2加密数据格式转换 
	 * @param b C1C2C3
	 * @return SM2Cipher
	 * @throws IOException
	 */
	public static byte[] SM2EncDataC1C2C3ToSM2Cipher(byte[] b) throws IOException {	
		int keylen=b[0]*8;
		byte[] x=new byte[keylen];
		byte[] y=new byte[keylen];
		byte[] hash	=new byte[32];
		byte[] enc	=new byte[b.length-keylen*2-32-1];		
		System.arraycopy(b, 1, x, 0, 32);
		System.arraycopy(b, 33, y, 0, 32);
		System.arraycopy(b, 65, enc, 0, enc.length);
		System.arraycopy(b, 65+enc.length, hash, 0, 32);
		ASN1EncodableVector	sm2enc=new ASN1EncodableVector();
		sm2enc.add(new ASN1Integer(new BigInteger(1,x)));
		sm2enc.add(new ASN1Integer(new BigInteger(1,y)));
		sm2enc.add(new DEROctetString(hash));
		sm2enc.add(new DEROctetString(enc));
		return new DERSequence(sm2enc).getEncoded();
	}
	/**
	 * SM2签名数据格式转换 
	 * @param b SM2Signature
	 * @return rs
	 * @throws IOException
	 */
	public static byte[]  SM2SignatureToRS(byte[] b) throws IOException {
		byte [] sign=new byte[64];
		DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(b))).readObject();
		byte[] r=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] s=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		System.arraycopy(r, r[0]==0x0?1:0, sign,0,r[0]==0x0?r.length-1:r.length);
		System.arraycopy(s, s[0]==0x0?1:0, sign,32, s[0]==0x0?s.length-1:s.length);
		return sign;
	}
	/**
	 * SM2签名数据格式转换
	 * @param b rs
	 * @return SM2Signature
	 * @throws IOException
	 */
	public static byte[] RSToSM2Signature(byte[] b) throws IOException {
		byte[] r=new byte[32];
		byte[] s=new byte[32];
		System.arraycopy(b, 0, r, 0, 32);
		System.arraycopy(b, 32,s, 0, 32);
		ASN1EncodableVector	sm2sign=new ASN1EncodableVector();
		sm2sign.add(new ASN1Integer(new BigInteger(1,r)));
		sm2sign.add(new ASN1Integer(new BigInteger(1,s)));
		return new DERSequence(sm2sign).getEncoded();
	}
}
