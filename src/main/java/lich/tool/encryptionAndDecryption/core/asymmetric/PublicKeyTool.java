package lich.tool.encryptionAndDecryption.core.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.X509Store;

import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.Base;

public class PublicKeyTool  extends Base{
	/**
	 *  x509获取PublicKey
	 * @param x509Certificate X509Certificate bytes
	 * @return PublicKey
	 * @throws IOException 
	 */
	public static PublicKey x509CertificateToPublicKey(byte [] x509Certificate) throws IOException{
		X509CertificateHolder	holder = new X509CertificateHolder(x509Certificate);
		byte[] pub_t=holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes();
		return toGMPublicKey(pub_t);
	}
	/**
	 * 加载X509证书
	 * @param x509Certificate X509Certificate bytes
	 * @return X509Certificate
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static X509Certificate 	loadX509Certificate(byte [] x509Certificate) throws CertificateException, IOException {
		X509CertificateHolder	holder = new X509CertificateHolder(x509Certificate);
		return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
	}
	/**
	 * 获取p7b证书链上所有证书
	 * @param p7b p7b p7c bytes
	 * @return X509Certificate [] 
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws OperatorCreationException 
	 * @throws CertException 
	 * @throws EncryptionAndDecryptionException 
	 */
	/**
	 * 获取p7b证书链上所有证书
	 * @param p7b p7b p7c bytes
	 * @param isCheckChain 是否校验证书链
	 * @return  X509Certificate [] 
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 * @throws CertException
	 * @throws EncryptionAndDecryptionException 证书链校验失败
	 */
	public static X509Certificate [] loadP7bToChain(byte [] p7b,boolean isCheckChain) throws CMSException, CertificateException, OperatorCreationException, CertException, EncryptionAndDecryptionException {
		 CMSSignedData sd = new CMSSignedData(p7b);
		 Store<X509CertificateHolder> ss=	 sd.getCertificates();
		 Collection<X509CertificateHolder> x=	 ss.getMatches(null);
		 Iterator<X509CertificateHolder> iterator=	x.iterator();
		 X509Certificate [] X509Certificates=new X509Certificate[x.size()];
		 int i=0;
		 ContentVerifierProvider cp=null;
		 while (iterator.hasNext()) {
				X509CertificateHolder x509CertificateHolder = iterator.next();
				if(isCheckChain) {
					if(i==0) {
						cp=	new JcaContentVerifierProviderBuilder().setProvider(BC).build(x509CertificateHolder);
						boolean b=x509CertificateHolder.isSignatureValid(cp);
						if(b!=true) {
							throw new EncryptionAndDecryptionException("根证校验失败："+x509CertificateHolder.getSubject().toString());
						}
					}else {
						boolean b=x509CertificateHolder.isSignatureValid(cp);
						if(b!=true) {
							throw new EncryptionAndDecryptionException("证书链校验失败："+x509CertificateHolder.getSubject().toString());
						}
					}	
				}
				X509Certificates[i]=new JcaX509CertificateConverter().setProvider(BC).getCertificate(x509CertificateHolder);
				i++;
		 }
		return X509Certificates;  
	}
	/**
	 *  获取p7b证书链上的证书
	 * @param p7b p7b p7c bytes
	 * @param isCheckChain 是否校验证书链
	 * @return X509Certificate
	 * @throws CMSException
	 * @throws CertificateException
	 * @throws OperatorCreationException 
	 * @throws CertException 
	 * @throws EncryptionAndDecryptionException 证书链校验失败
	 */
	public static X509Certificate loadP7bToX509Certificate(byte [] p7b,boolean isCheckChain) throws CMSException, CertificateException, OperatorCreationException, CertException, EncryptionAndDecryptionException {
		 CMSSignedData sd = new CMSSignedData(p7b);
		 Store<X509CertificateHolder> ss=	 sd.getCertificates();
		 Collection<X509CertificateHolder> x=	 ss.getMatches(null);
		 Iterator<X509CertificateHolder> iterator=	x.iterator();
		 X509CertificateHolder x509CertificateHolder=null;
		 int i=0;
		 ContentVerifierProvider cp=null;
		 while (iterator.hasNext()) {
				x509CertificateHolder = iterator.next();	
				if(isCheckChain) {
					if(i==0) {
						cp=	new JcaContentVerifierProviderBuilder().setProvider(BC).build(x509CertificateHolder);
						boolean b=x509CertificateHolder.isSignatureValid(cp);
						if(b!=true) {
							throw new EncryptionAndDecryptionException("根证校验失败："+x509CertificateHolder.getSubject().toString());
						}
					}else {
						boolean b=x509CertificateHolder.isSignatureValid(cp);
						if(b!=true) {
							throw new EncryptionAndDecryptionException("证书链校验失败："+x509CertificateHolder.getSubject().toString());
						}
					}	
				}
				i++;
		 }
		return new JcaX509CertificateConverter().setProvider(BC).getCertificate(x509CertificateHolder);  
	}
	/**
	 *  证书列表转换证书链
	 * @param certificateChain 证书列表
	 * @param isCheckChain 是否校验证书链
	 * @return X509Certificate
	 * @throws CMSException
	 * @throws OperatorCreationException 
	 * @throws CertificateException
	 * @throws CertException 
	 * @throws EncryptionAndDecryptionException 证书链校验失败
	 */
	public static byte[] certificateChainToP7b(X509Certificate [] certificateChain,boolean isCheckChain) throws CMSException, IOException, OperatorCreationException, CertificateException, CertException, EncryptionAndDecryptionException {
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	    CMSProcessableByteArray msg = new CMSProcessableByteArray("".getBytes());
	    int i=0;
	    ContentVerifierProvider cp=null;
	    for(X509Certificate x509Certificate : certificateChain) {
	    	X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
	    	if(i==0) {
				cp=	new JcaContentVerifierProviderBuilder().setProvider(BC).build(x509CertificateHolder);
				boolean b=x509CertificateHolder.isSignatureValid(cp);
				if(b!=true) {
					throw new EncryptionAndDecryptionException("根证校验失败："+x509CertificateHolder.getSubject().toString());
				}
			}else {
				boolean b=x509CertificateHolder.isSignatureValid(cp);
				if(b!=true) {
					throw new EncryptionAndDecryptionException("证书链校验失败："+x509CertificateHolder.getSubject().toString());
				}
			}
	    	i++;
		}
	    JcaCertStore store = new JcaCertStore(Arrays.asList(certificateChain));
	    gen.addCertificates(store);
	    CMSSignedData signedData = gen.generate(msg);
	    return signedData.getEncoded();
	}
	/**
	 * 证书列表转换证书链
	 * @param certificateChain [i][证书bytes]
	 * @param isCheckChain
	 * @return p7b bytes
	 * @throws CMSException
	 * @throws IOException
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws CertException
	 * @throws EncryptionAndDecryptionException
	 */
	public static byte[] certificateChainToP7b(byte [][] certificateChain,boolean isCheckChain) throws CMSException, IOException, OperatorCreationException, CertificateException, CertException, EncryptionAndDecryptionException {
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	    CMSProcessableByteArray msg = new CMSProcessableByteArray("".getBytes());
	    int i=0;
	    ContentVerifierProvider cp=null;
	    List l=new ArrayList();
	    for(byte [] x509Certificate : certificateChain) {
	    	X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate);
	    	l.add(x509CertificateHolder);
	    	if(i==0) {
				cp=	new JcaContentVerifierProviderBuilder().setProvider(BC).build(x509CertificateHolder);
				boolean b=x509CertificateHolder.isSignatureValid(cp);
				if(b!=true) {
					throw new EncryptionAndDecryptionException("根证校验失败："+x509CertificateHolder.getSubject().toString());
				}
			}else {
				boolean b=x509CertificateHolder.isSignatureValid(cp);
				if(b!=true) {
					throw new EncryptionAndDecryptionException("证书链校验失败："+x509CertificateHolder.getSubject().toString());
				}
			}
	    	i++;
		}
	    JcaCertStore store = new JcaCertStore(l);
	    gen.addCertificates(store);
	    CMSSignedData signedData = gen.generate(msg);
	    return signedData.getEncoded();
	}
	
	
	/**
	 * 生成公钥证书
	 * @param pki 公钥信息
	 * @param pk 公钥
	 * @return 公钥证书
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	public static X509Certificate getX509Certificate(PublicKeyInfo pki,PublicKey pk) throws OperatorCreationException, IOException, CertificateException {
		X500Name subject=new X500Name(pki.getSubject());
		X509CertificateHolder  x509CertificateHolder=null;
		if(pk instanceof  BCECPublicKey) {
			SubjectPublicKeyInfo spki=new SubjectPublicKeyInfo(
									new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1"),new ASN1ObjectIdentifier("1.2.156.10197.1.301")), 
									((BCECPublicKey)pk).getQ().getEncoded(false)
								);
			X509v3CertificateBuilder X509=new X509v3CertificateBuilder(X500Name.getInstance(rootGMX509Certificate.getSubjectX500Principal().getEncoded()),pki.getSerial(),pki.getNotBefore(),pki.getNotAfter(),subject,spki);		
			ContentSigner sigGen = new JcaContentSignerBuilder(pki.getSignatureAlgorithm()==null?ProviderMode.Asymmetric.GM.Signature.SM3WITHSM2:pki.getSignatureAlgorithm()).setProvider(BC).build(rootGMPrivateKey);
			KeyPurposeId [] KeyPurposeIds= {KeyPurposeId.id_kp_serverAuth,KeyPurposeId.id_kp_emailProtection};
			X509.addExtension(Extension.keyUsage, false,new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
	        // 设置扩展密钥用法：客户端身份认证、安全电子邮件
	        .addExtension(Extension.extendedKeyUsage, false,new ExtendedKeyUsage( KeyPurposeIds))
	        .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
	        // Netscape Cert Type SSL客户端身份认证
	        .addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslClient));
			x509CertificateHolder= 	X509.build(sigGen);
			
		}else {
			BCRSAPublicKey bcr=	(BCRSAPublicKey)pk;
			SubjectPublicKeyInfo spki=new SubjectPublicKeyInfo(
					 ASN1Sequence.getInstance(bcr.getEncoded())
			);
			X509v3CertificateBuilder X509=new X509v3CertificateBuilder(X500Name.getInstance(rootRSAX509Certificate.getSubjectX500Principal().getEncoded()),pki.getSerial(),pki.getNotBefore(),pki.getNotAfter(),subject,spki);
			X509.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
			ContentSigner sigGen = new JcaContentSignerBuilder(pki.getSignatureAlgorithm()==null?ProviderMode.Asymmetric.RSA.Signature.SHA256WithRSA:pki.getSignatureAlgorithm()).setProvider(BC).build(rootRSAPrivateKey);
			x509CertificateHolder= 	X509.build(sigGen);	
		}
		return new JcaX509CertificateConverter().setProvider(BC).getCertificate(x509CertificateHolder);
	}
	/**
	 * GM公钥生成publicKey
	 * @param P 04|x|y
	 * @return PublicKey
	 */
	public static PublicKey toGMPublicKey(byte[] P) {
		SubjectPublicKeyInfo spki=new SubjectPublicKeyInfo(
									new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.10045.2.1"),new ASN1ObjectIdentifier("1.2.156.10197.1.301")), 
									P
								);
		
		try {
			Class cls =Class.forName("org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey");
			Constructor  c=cls.getDeclaredConstructor(String.class,SubjectPublicKeyInfo.class,ProviderConfiguration.class);
			c.setAccessible(true); 
			return 	(BCECPublicKey)c.newInstance("EC", spki,BouncyCastleProvider.CONFIGURATION);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
			
	}
	/**
	 * RSA公钥生成公钥证书 参数N 65537
	 * @param N 公钥
	 * @return BCRSAPublicKey
	 */
	public static PublicKey toRSAPublicKey(byte[] N) {
		byte[] E= {0x01,0x00,0x01};
		return toRSAPublicKey(N,E);
			
	}
	/**
	 * RSA公钥生成公钥证书
	 * @param E 公钥
	 * @param N 公钥参数
	 * @return BCRSAPublicKey
	 */
	public static PublicKey toRSAPublicKey(byte[] N,byte[] E) {
		
		try {
			Class cls =Class.forName("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey");
			Constructor  c=cls.getDeclaredConstructor(RSAKeyParameters.class);
			c.setAccessible(true); 
			return 	(BCRSAPublicKey)c.newInstance(new RSAKeyParameters(false, new BigInteger(N), new BigInteger(E)));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
			
	}
	/**
	 * 获取公钥byte
	 * @param publicKey 公钥
	 * @return GM P 04|x|y
	 * 		   RSA N 
	 * @throws EncryptionAndDecryptionException
	 */
	public static byte[] getPublicKeyByte(PublicKey publicKey) throws EncryptionAndDecryptionException {
		if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.GM.KeyPairGenerator.EC)) {
			BCECPublicKey gmkey=(BCECPublicKey)publicKey;
			ECPoint  ecp=	gmkey.getQ();
			byte [] ret=new byte[65];
			ret[0]=4;
			System.arraycopy(ecp.getXCoord().getEncoded(), 0, ret, 1, 32);
			System.arraycopy(ecp.getYCoord().getEncoded(), 0, ret, 33, 32);
			return ret;
    	}else if(publicKey.getAlgorithm().equals(ProviderMode.Asymmetric.RSA.KeyPairGenerator.RSA)){
    		BCRSAPublicKey rsakey=(BCRSAPublicKey)publicKey;
    		
    		return	rsakey.getModulus().toByteArray();
    	}else {
    		throw new EncryptionAndDecryptionException(publicKey.getAlgorithm()+"不支持的密钥类型");
    	}
	}
	
	
}
