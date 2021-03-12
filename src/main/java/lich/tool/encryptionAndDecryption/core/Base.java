package lich.tool.encryptionAndDecryption.core;


import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.core.asymmetric.PrivateKeyTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;
import lich.tool.encryptionAndDecryption.ext.DefaultSM4Ext;
import lich.tool.encryptionAndDecryption.ext.SM1Ext;
import lich.tool.encryptionAndDecryption.ext.SM4Ext;

/**
 * 基础配置类
 * @author liuch
 *
 */
public class Base {
	protected final static X9ECParameters x9ECParameters;
	protected final static ECParameterSpec ecParameterSpec;
	protected final static ECDomainParameters ecDomainParameters;
	
	protected  static PrivateKey  rootGMPrivateKey;
	protected  static X509Certificate rootGMX509Certificate;
	protected  static PrivateKey  rootRSAPrivateKey;
	protected  static X509Certificate rootRSAX509Certificate;

	private static SM1Ext sm1ext;
	private static SM4Ext sm4ext=new DefaultSM4Ext();
	protected static java.security.Provider  BC;
	static {
		BC=new BouncyCastleProvider();
		x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
		ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
		ecDomainParameters=new ECDomainParameters(x9ECParameters);
		try {
			
			byte[] d=Hex.decodeStrict("54f75e13431f7c2ebb6c0cd6e6b3af8b3d1203c8cc9ee6de63215f249b7c113b");
			String rootGMCert="MIIBbTCCAROgAwIBAgIGAXbbDsqKMAoGCCqBHM9VAYN1MBwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQDDARsaWNoMB4XDTIwMTIzMTE2MDAwMFoXDTM1MTIzMTE1NTk1OVowHDELMAkGA1UEBhMCQ04xDTALBgNVBAMMBGxpY2gwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQeyRxm12te20LpKRFOlSiM5dDrcDtfbcTeCNetzeH37VATYu/WM3Wq4vnvb32RCMLqurGfCYx4aqWXL11Vn/dGo0EwPzALBgNVHQ8EBAMCBsAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMEMBEGCWCGSAGG+EIBAQQEAwIHgDAKBggqgRzPVQGDdQNIADBFAiEA27AoJSd+Ra9MvOLwr6eW1wTpxSzqL35gU+wjzy5/SVACIE8RPYc9pXxnWI6+hdsduNosJRVvpKow/ofBmQKON4QX";
			rootGMX509Certificate=PublicKeyTool.loadX509Certificate(Base64.decode(rootGMCert));
			rootGMPrivateKey=PrivateKeyTool.toGMPrivateKey(d, PublicKeyTool.getPublicKeyByte(rootGMX509Certificate.getPublicKey()));
			byte[] pkcs8=Hex.decodeStrict("308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100d97fec79fae509e8eefcc0efb3c1e2aec310f24e29490f4b09fb3c850311999ca8fcc59fa06e1b2aa6835b63f665c70df5afe4d46a55d882697f72e17f18099b0be8422a31a9666de8b65431395db3916bedd9b4e6283b8549aea0902509543f499cc4975dc3e7aa2ce29dae89c473d411d4a9deda99456dd6231a09a859ab638d8017c3a06c65c24910be2a3418752ab65bd5c9c41b63f6a75eda08104cbca35a911d9c244c99a676e3ba13c9d49de87b67ff3a281f9ea86766a9da16754616acfe14914f7c0bf87e393c075c91ed60a5d82feeccaa1112cae6a34136549733e9479cef4910fd8772198c1830a3822fa20bcd8e6f44d7bcf0db283053c9ee870203010001028201002c8c1df431e61d6c7f1e77a9e0c872545711ae7f41c77c01638ef8ab49a09e34cf0bceb24e1a9f27d2290f5bdf08a387816dc0519d61edd1702831706c269139176c3fb902a8ee98ce5421d45f2a88efdd0a3f4fe4e012a8cf199c3b49caaa5db8070ae0f1cc813382b3fb95d713cca17ff16dc57e426c4cfdd1fcb043b1f1ff3624d9f0d6acc3545366c8ec61cb4c33a8da9f4f67d8c9533f37736736e83cfab96977246f0cab7c0330efff62e6defd366362325390ac2db98eb0fe8336ddcbd85a16dee06a88719b21c8d32952b640508e53051e03fc12f10cd6a9fcce8f147263174d0ee68e24640dac39bcaa48f20963f4443110c0b83c579536dd2f5e8102818100f74c2e1dd4dce0513e681d25b0229e70a9ac7bca35fdb371c1713615c7421dc821fc2839e0d7b5e17cdb875792e8be67bad5ef100b9196d4a2f6d11cf54b04e82d2a6f6b9dcecc22f10d09eb1738d1a95d9996d57938deb2920d283f25464370cc60db1000aca6ceff7bd9cabcf21c1e3ebd1229be86462b1aca4b75b54a60c702818100e1274dfd6fe8d0a8a8f3ba306c8bdb7033e41eb424795372c9eaeb9fd9f0a0bec22e4dc885c45edd5183db134769dcf21b83282e6d22083d3d35d6c54008f484cbcf4fc381db285f900b86d40157358ec22871dc24a35f719cf617f3e80a927d2fde15eb243d428b2aec926822a81e41b5954dd2c906177ddded486646b9c44102818100b9028f45d62860d1a744b0f9af2a572aa665da3ecfe1bbcc1112a789e786b94d2ecfbd307fdc21c04e6ed67457fe33e4dacc8e8b8c7c214177a1fb941497495681e3cb73d19e12eed9340e05895c02cf18ad7d40bbee25fda6729d7790655eb316d4274f7391b74209b5189d2a7a5f3ae968fe1ba8e43fbea3ce5062017d61a502818100cb0f49b54292b46d0843182ec816b287d524edd405f92e1b9ea3b271ee7aa85ea27e64446ef015a680f7ec42cceb5b0b3768e87a468ea4e3a62ac2520f58843ea81986948aaeff1080b704987bc50d567d2140df0c64139641bb690adec17a305155786b23b9e423e3488d1a41f761a25d841436007af000e280380595cfc08102818100d06baac577b8fa4b386a3dbfecd84d3a6d6a674b87fd19651bf9293c831f0a65fb7691a7742ede666f8a6b29bfe359bd3b7d066db4fda10ac7eeb2540ebff284e69d43377aff05954298bf60c06f9a2b9200951322a9d0de5a5ee696b57d737b2551ff433508c02f40f531be1d97bde7c23640a7478ec4b2c9eac98407d94e0a");
			String rootRSACert="MIICtjCCAZ6gAwIBAgIGAXbbC//TMA0GCSqGSIb3DQEBCwUAMBwxCzAJBgNVBAYTAkNOMQ0wCwYDVQQDDARsaWNoMB4XDTIwMTIzMTE2MDAwMFoXDTM1MTIzMTE1NTk1OVowHDELMAkGA1UEBhMCQ04xDTALBgNVBAMMBGxpY2gwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZf+x5+uUJ6O78wO+zweKuwxDyTilJD0sJ+zyFAxGZnKj8xZ+gbhsqpoNbY/Zlxw31r+TUalXYgml/cuF/GAmbC+hCKjGpZm3otlQxOV2zkWvt2bTmKDuFSa6gkCUJVD9JnMSXXcPnqizina6JxHPUEdSp3tqZRW3WIxoJqFmrY42AF8OgbGXCSRC+KjQYdSq2W9XJxBtj9qde2ggQTLyjWpEdnCRMmaZ247oTydSd6Htn/zooH56oZ2ap2hZ1Rhas/hSRT3wL+H45PAdcke1gpdgv7syqERLK5qNBNlSXM+lHnO9JEP2HchmMGDCjgi+iC82Ob0TXvPDbKDBTye6HAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKiNmgaoiqADZVinJphe8BFjWjkmvHoAuSfWrEP4/xqZ0bmJtviMB+Uazh0UuA1PSd6D/nO3sUyBMvtQbKRGLFRDPk8rfVONEQXxIVsyhAUuIxAXncfn6+kNJMaPUaO/ynS9Q4pPzAHlgY+/d9vU5fn7zU58zMkn2YO0pbPguScbls/q3pcT3+Ij2i7RQAeDUX7ixyaxmVnVMC5F1rMiBR/mki2IyzpzfdyQqUfBlT4mNrbTA+9mOGHDjledrE3J7M7cJlU3mCOugNo67WCsQNSPACRKPBwo9OwiDx9aD4r81xuZM+JFsBQ4bYQdF2txR+xwa8C8204c1EZMHxXP3jI=";
			rootRSAX509Certificate=PublicKeyTool.loadX509Certificate(Base64.decode(rootRSACert));
			rootRSAPrivateKey=PrivateKeyTool.toRSAPrivateKey(pkcs8);		
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (EncryptionAndDecryptionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	/**
	 * 配置SM1实现
	 * @param sm1ext
	 */
	public static void setSm1ext(SM1Ext sm1ext) {
		Base.sm1ext = sm1ext;
	}
	/**
	 * 配置SM4实现
	 * @param sm4ext
	 */
	public static void setSm4ext(SM4Ext sm4ext) {
		Base.sm4ext = sm4ext;
	}
	/**
	 * 配置GM根证
	 * @param pk PrivateKey
	 * @param cert X509Certificate
	 */
	public void setGMroot(PrivateKey pk,X509Certificate cert) {
		rootGMPrivateKey=pk;
		rootGMX509Certificate=cert;
	}
	/**
	 * 配置RSA根证
	 * @param pk PrivateKey
	 * @param cert X509Certificate
	 */
	public void setRSAroot(PrivateKey pk,X509Certificate cert) {
		rootRSAPrivateKey=pk;
		rootRSAX509Certificate=cert;
	}
	
	/**
	 * 获取GM根 PrivateKey
	 * @return PrivateKey
	 */
	public static PrivateKey getRootGMPrivateKey() {
		return rootGMPrivateKey;
	}
	/**
	 * 获取GM根 X509Certificate
	 * @return X509Certificate
	 */
	public static X509Certificate getRootGMX509Certificate() {
		return rootGMX509Certificate;
	}
	/**
	 * 获取RSA根 PrivateKey
	 * @return PrivateKey
	 */
	public static PrivateKey getRootRSAPrivateKey() {
		return rootRSAPrivateKey;
	}
	/**
	 * 获取RSA根 X509Certificate
	 * @return X509Certificate
	 */
	public static X509Certificate getRootRSAX509Certificate() {
		return rootRSAX509Certificate;
	}
	protected static SM1Ext getSm1ext() throws EncryptionAndDecryptionException {
		if(sm1ext==null)throw new EncryptionAndDecryptionException("解密需要SM1实现，当前未实现");
		return sm1ext;
	}

	protected static SM4Ext getSm4ext() throws EncryptionAndDecryptionException {
		if(sm4ext==null)throw new EncryptionAndDecryptionException("解密需要SM4实现，当前未实现");
		return sm4ext;
	}
	
	
}
