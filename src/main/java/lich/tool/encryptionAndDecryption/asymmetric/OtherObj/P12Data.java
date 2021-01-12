package lich.tool.encryptionAndDecryption.asymmetric.OtherObj;

import java.security.PrivateKey;
import java.security.cert.Certificate;
public class P12Data {
	/**
	 * 公钥证书
	 */
	private Certificate cert;
	/**
	 * 私钥
	 */
	private PrivateKey privateKey;
	/**
	 * 证书链
	 */
	private Certificate[] certificateChain;
	
	public P12Data(Certificate cert, PrivateKey privateKey, Certificate[] certificateChain) {
		super();
		this.cert = cert;
		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
	}
	public Certificate getCert() {
		return cert;
	}
	public void setCert(Certificate cert) {
		this.cert = cert;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	public Certificate[] getCertificateChain() {
		return certificateChain;
	}
	public void setCertificateChain(Certificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}	
}