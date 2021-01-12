package lich.tool.encryptionAndDecryption.core.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.Base;


public class PrivateKeyTool  extends Base{
	/**
	 * GM私钥加载
	 * @param d 私钥
	 * @param P 公钥
	 * @return BCECPrivateKey
	 */
	public static PrivateKey toGMPrivateKey(byte [] d,byte [] P){
		ECPrivateKeyParameters ecp=	new ECPrivateKeyParameters(new BigInteger(1,d),ecDomainParameters);
		return	 new BCECPrivateKey("EC", ecp,(BCECPublicKey)PublicKeyTool.toGMPublicKey(P),(ECParameterSpec)null,BouncyCastleProvider.CONFIGURATION);	
	}
	
	
	/**
	 * GM私钥加载（使用内置密钥解密）
	 * @param doubleprvkey EnvelopedKeyBlob私钥保护结构体 详见GM/T-0016-2012
	 * @return BCECPrivateKey
	 * @throws Exception
	 */
	public static PrivateKey toGMPrivateKeyByEnvelopedKeyBlob(byte [] doubleprvkey) throws Exception{
		return toGMPrivateKeyByEnvelopedKeyBlob( doubleprvkey,rootGMPrivateKey);
	}
	/**
	 * GM私钥加载
	 * @param doubleprvkey EnvelopedKeyBlob私钥保护结构体 详见GM/T-0016-2012
	 * @param privateKey 解密私钥
	 * @return BCECPrivateKey
	 * @throws Exception
	 */
	public static PrivateKey toGMPrivateKeyByEnvelopedKeyBlob(byte [] doubleprvkey,PrivateKey privateKey) throws Exception {
		byte[] puk=new byte[65];
		byte[]	sm2EncData=	CbEncryptedPrivKeygetSM2EncDataC1C2C3(doubleprvkey);
		byte[] key=AsymmetricTool.decrypt(sm2EncData, privateKey, ProviderMode.Asymmetric.GM.Cipher.SM2WITHSM3);        
		puk[0]=0x04;
		System.arraycopy(doubleprvkey,112, puk, 1, 32);
		System.arraycopy(doubleprvkey, 176, puk,33, 32);
		byte[] cbEncryptedPrivKey=new byte[32];
		System.arraycopy(doubleprvkey, 44, cbEncryptedPrivKey, 0, 32);	
		byte[] prk=(doubleprvkey[4]==0x01&&doubleprvkey[5]==0x01)?getSm1ext().decrypt(cbEncryptedPrivKey,key):getSm4ext().decrypt(cbEncryptedPrivKey,key);
		byte[] nprk=new byte[prk[0]==0x1?33:32];
		System.arraycopy(prk, 0, nprk, prk[0]==0x1?1:0, 32);
		prk=nprk;
		return PrivateKeyTool.toGMPrivateKey(prk, puk);
	}
	/**
	 * GM私钥导出（使用内置密钥加密）
	 * @param gmPrivateKey BCECPrivateKey
	 * @return EnvelopedKeyBlob
	 * @throws Exception 
	 * @throws EncryptionAndDecryptionException 
	 */
	public static  byte[] toEnvelopedKeyBlobByGMPrivateKey(PrivateKey gmPrivateKey) throws EncryptionAndDecryptionException, Exception{
		return toEnvelopedKeyBlobByGMPrivateKey(gmPrivateKey, rootGMX509Certificate.getPublicKey());
	}
	/**
	 * GM私钥导出
	 * @param gmPrivateKey 被导出的密钥
	 * @param encGmPublicKey 加密密钥
	 * @return EnvelopedKeyBlob
	 * @throws Exception 
	 * @throws EncryptionAndDecryptionException 
	 */
	public static  byte[] toEnvelopedKeyBlobByGMPrivateKey(PrivateKey gmPrivateKey,PublicKey encGmPublicKey) throws EncryptionAndDecryptionException, Exception{
		byte [] envelopedKeyBlob=new byte[388];
		envelopedKeyBlob[0]=0x01;
		envelopedKeyBlob[4]=0x01;
		envelopedKeyBlob[5]=0x04;
		envelopedKeyBlob[5]=0x04;
		envelopedKeyBlob[9]=0x01;
		BCECPrivateKey ecgmBcecPrivateKey=(BCECPrivateKey)gmPrivateKey;
		Field f=BCECPrivateKey.class.getDeclaredField("publicKey");
		f.setAccessible(true);
		byte [] P=	((DERBitString)f.get(ecgmBcecPrivateKey)).getOctets();
		byte [] pxy=new byte[132];
		pxy[1]=0x01;
		System.arraycopy(P, 1, pxy, 36, 32);
		System.arraycopy(P, 33, pxy, 100, 32);
		byte[] d=ecgmBcecPrivateKey.getD().toByteArray();
		byte[] pwd = new byte[16];
		new SecureRandom().nextBytes(pwd);
		byte[] enc=getSm4ext().encrypt(d, pwd);
		System.arraycopy(enc, 0, envelopedKeyBlob, 44, 32);	
		System.arraycopy(pxy,0, envelopedKeyBlob, 76, 132);
		byte[] encPwd =AsymmetricTool.encrypt(pwd, encGmPublicKey, ProviderMode.Asymmetric.GM.Cipher.SM2);
		DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(encPwd))).readObject();
		byte[] x=	((ASN1Integer)sequence.getObjectAt(0)).getValue().toByteArray();
		byte[] y=	((ASN1Integer)sequence.getObjectAt(1)).getValue().toByteArray();
		byte[] hash=	((DEROctetString)sequence.getObjectAt(2)).getOctets();
		enc=	((DEROctetString)sequence.getObjectAt(3)).getOctets();	
		System.arraycopy(x, x.length==32?0:1,envelopedKeyBlob, 240, 32);
		System.arraycopy(y, y.length==32?0:1,envelopedKeyBlob, 304, 32);
		System.arraycopy(enc, 0, envelopedKeyBlob, 372, 16);
		envelopedKeyBlob[368]=0x10;
		System.arraycopy(hash, 0, envelopedKeyBlob, 336, 32);
		return envelopedKeyBlob;
	}
	/**
	 * GM私钥加载 （使用内置密钥解密）
	 * @param doubleprvkey signedAndEnvelopedData 私钥保护结构体 详见GM/T-0010-2012
	 * @param puk 待解密私钥的公钥 04|x|y
	 * @return BCECPrivateKey
	 * @throws Exception
	 */
	public static PrivateKey toGMPrivateKeyBySignedAndEnvelopedData(byte [] doubleprvkey,byte[] puk) throws Exception{
		return toGMPrivateKeyBySignedAndEnvelopedData( doubleprvkey,rootGMPrivateKey,puk);
	}
	/**
	 * GM私钥加载 
	 * @param doubleprvkey signedAndEnvelopedData 私钥保护结构体 详见GM/T-0010-2012
	 * @param privateKey 解密私钥
	 * @param puk 待解密私钥的公钥 04|x|y
	 * @return BCECPrivateKey
	 * @throws Exception
	 */
	public static PrivateKey toGMPrivateKeyBySignedAndEnvelopedData(byte [] doubleprvkey,PrivateKey privateKey,byte[] puk) throws Exception{
		DLSequence sequence = (DLSequence) new ASN1InputStream(new ByteArrayInputStream(doubleprvkey)).readObject();
		DLSequence pukeinfo = (DLSequence)(((DLTaggedObject)sequence.getObjectAt(1)).getObject());
		DLSequence pukeinfo1=(DLSequence)((DLSet)pukeinfo.getObjectAt(1)).getObjectAt(0);
		DLSequence puke=(DLSequence)new ASN1InputStream(new ByteArrayInputStream(((DEROctetString)(pukeinfo1.getObjectAt(3))).getOctets())).readObject();
		byte[] key=AsymmetricTool.decrypt(puke.getEncoded(), privateKey, ProviderMode.Asymmetric.GM.Cipher.SM2WITHSM3);
		byte[] cbEncryptedPrivKey=((DEROctetString)((DERTaggedObject)((DERSequence)pukeinfo.getObjectAt(3)).getObjectAt(2)).getObject()).getOctets();
		byte[] prk=(((DERSequence)pukeinfo.getObjectAt(3)).getObjectAt(1)).toString().equals("[1.2.156.10197.1.102]")?getSm1ext().decrypt(cbEncryptedPrivKey,key):getSm4ext().decrypt(cbEncryptedPrivKey,key);			
		byte[] nprk=new byte[prk[0]==0x1?33:32];
		System.arraycopy(prk, 32, nprk, prk[0]==0x1?1:0, 32);
		prk=nprk;	
		return PrivateKeyTool.toGMPrivateKey(prk, puk);
	}

	
	
	/**
	 * rsa pkcs8 to PrivateKey
	 * @param pk pkcs8格式私钥匙
	 * @return BCRSAPrivateKey 或null
	 */
	public static PrivateKey toRSAPrivateKey(byte [] pk) {
		try {
			DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(pk))).readObject();
			sequence = (DLSequence) (new ASN1InputStream(((DEROctetString)sequence.getObjectAt(2)).getOctetStream())).readObject();
			BigInteger n = ((ASN1Integer)sequence.getObjectAt(1)).getValue();;
			BigInteger e =  ((ASN1Integer)sequence.getObjectAt(2)).getValue();
			BigInteger d =  ((ASN1Integer)sequence.getObjectAt(3)).getValue();
			BigInteger p = ((ASN1Integer)sequence.getObjectAt(4)).getValue();
			BigInteger q =  ((ASN1Integer)sequence.getObjectAt(5)).getValue();
			BigInteger dP = ((ASN1Integer)sequence.getObjectAt(6)).getValue();
			BigInteger dQ = ((ASN1Integer)sequence.getObjectAt(7)).getValue();;
			BigInteger qInv =((ASN1Integer)sequence.getObjectAt(8)).getValue();;
			return toRSAPrivateKey(n,e,d,p,q,dP,dQ,qInv);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
	}
	private static PrivateKey toRSAPrivateKey(BigInteger n,BigInteger e,BigInteger d,BigInteger p,BigInteger q,BigInteger dP,BigInteger dQ,BigInteger qInv){
		RSAPrivateCrtKeyParameters rpc=	 new RSAPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv);
		try {
			Class cls =Class.forName("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey");
			Constructor  c=cls.getDeclaredConstructor(RSAPrivateCrtKeyParameters.class);
			c.setAccessible(true); 
			return 	(BCRSAPrivateCrtKey)c.newInstance(rpc);
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}		
	}
	
	private static byte[] CbEncryptedPrivKeygetSM2EncDataC1C2C3(byte[] b) throws IOException{
		byte[] encData=new byte[113];
		encData[0]=0x04;
		System.arraycopy(b, 240,encData, 1, 32);
		System.arraycopy(b, 304,encData, 33, 32);
		System.arraycopy(b, 372, encData, 65, 16);
		System.arraycopy(b, 336, encData, 81, 32);
		return encData;
	}
}
