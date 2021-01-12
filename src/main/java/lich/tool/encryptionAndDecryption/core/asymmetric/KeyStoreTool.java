package lich.tool.encryptionAndDecryption.core.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.P12Data;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.Base;

/**
 * 密钥对工具类
 * @author liuch
 *
 */
public class KeyStoreTool extends Base{
	/**
	 * 导出p12
	 * @param keyPair 密钥对
	 * @param pki 公钥信息
	 * @param alias 别名
	 * @param pwd 密码
	 * @return p12
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] toPKCS12(KeyPair keyPair,PublicKeyInfo pki,String alias,String pwd) throws KeyStoreException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance(ProviderMode.Asymmetric.KeyStore.PKCS12,BC);
		keyStore.load(null, null);
		keyStore.setKeyEntry(alias, keyPair.getPrivate(), pwd.toCharArray(), new Certificate[]{ PublicKeyTool.getX509Certificate(pki, keyPair.getPublic()) });
		ByteArrayOutputStream fos = new ByteArrayOutputStream();
		keyStore.store(fos, pwd.toCharArray());
		return fos.toByteArray();
	}
	/**
	 *  导出p12
	 * @param prk 私钥
	 * @param certs 公钥证书
	 * @param alias 别名
	 * @param pwd 密码
	 * @return p12
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] toPKCS12(PrivateKey prk,Certificate[] certs,String alias,String pwd) throws KeyStoreException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance(ProviderMode.Asymmetric.KeyStore.PKCS12,BC);
		keyStore.load(null, null);
		keyStore.setKeyEntry(alias, prk, pwd.toCharArray(), certs);
		ByteArrayOutputStream fos = new ByteArrayOutputStream();
		keyStore.store(fos, pwd.toCharArray());
		return fos.toByteArray();
	}
	/**
	 * 加载p12
	 * @param p12 p12
	 * @param pwd 密码
	 * @return P12Data
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 */
	public static P12Data loadPKCS12(byte [] p12,String pwd) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
		KeyStore keyStore = KeyStore.getInstance(ProviderMode.Asymmetric.KeyStore.PKCS12,BC);
		keyStore.load(new ByteArrayInputStream(p12), pwd.toCharArray());
		Enumeration enumas = keyStore.aliases(); 
        String keyAlias = null;  
        if (enumas.hasMoreElements()) {  
            keyAlias = (String)enumas.nextElement(); 
        }  
      
        PrivateKey prikey = (PrivateKey) keyStore.getKey(keyAlias, pwd.toCharArray());  
        Certificate cert = keyStore.getCertificate(keyAlias);  
        Certificate[] certificateChain=  keyStore.getCertificateChain(keyAlias);
        return new P12Data(cert,prikey,certificateChain);
	}
	/**
	 * 生成p10证书申请请求
	 * @param privateKey 私钥
	 * @param publicKey 公钥
	 * @param dn dn
	 * @param algorithm 签名标识
	 * @return p10der
	 * @throws OperatorCreationException
	 * @throws IOException
	 * @throws EncryptionAndDecryptionException
	 */
	public static byte[] toPKCS10(PrivateKey privateKey,PublicKey publicKey,String dn,String algorithm) throws OperatorCreationException, IOException, EncryptionAndDecryptionException{
		 X500Principal principal = new X500Principal(dn);
		if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
			ASN1EncodableVector certificationRequestInfo  = new ASN1EncodableVector();
			certificationRequestInfo.add(new ASN1Integer(0));
			certificationRequestInfo.add(new ASN1InputStream(new ByteArrayInputStream(principal.getEncoded())).readObject());
			SubjectPublicKeyInfo spki=new SubjectPublicKeyInfo(
					new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1"),new ASN1ObjectIdentifier("1.2.156.10197.1.301")), 
					((BCECPublicKey)publicKey).getQ().getEncoded(false)
				);
			certificationRequestInfo.add(new ASN1InputStream(new ByteArrayInputStream(spki.getEncoded())).readObject());
			DERSequence	certificationRequestInfoSeq=new DERSequence(certificationRequestInfo);
			ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider(BC).build(privateKey);
	        OutputStream sOut = signer.getOutputStream();
	        sOut.write(certificationRequestInfoSeq.getEncoded());
	        sOut.close();
	        byte[] sign= signer.getSignature();
			AlgorithmIdentifier signatureAlgorithm=signer.getAlgorithmIdentifier();
			ASN1EncodableVector certificationRequest  = new ASN1EncodableVector();
			certificationRequest.add(certificationRequestInfoSeq);
			ASN1EncodableVector	algorithmIdentifier = new ASN1EncodableVector();
			algorithmIdentifier.add(signatureAlgorithm.getAlgorithm());
			algorithmIdentifier.add(DERNull.INSTANCE);
			certificationRequest.add(new DERSequence(algorithmIdentifier));
			certificationRequest.add(new DERBitString(new ASN1InputStream(new ByteArrayInputStream(sign)).readObject()));
			return new DERSequence(certificationRequest).getEncoded();	
    	}else if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
 	        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
 	                principal,
 	                publicKey
 	        );
 	        ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider(BC).build(privateKey);
 	        PKCS10CertificationRequest pkcs10 = p10Builder.build(signer);
 	        return pkcs10.getEncoded();
    	}else {
    		throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持的密钥类型");
    	}             
	}
	/**
	 * 生成p10证书申请请求
	 * @param kp 密钥对
	 * @param dn dn
	 * @param algorithm 签名标识
	 * @return p10der
	 * @throws OperatorCreationException
	 * @throws IOException
	 * @throws EncryptionAndDecryptionException
	 */
	public static byte[] toPKCS10(KeyPair kp,String dn,String algorithm) throws OperatorCreationException, IOException, EncryptionAndDecryptionException {
		return toPKCS10(kp.getPrivate(),kp.getPublic(), dn, algorithm);
	} 
	
}
