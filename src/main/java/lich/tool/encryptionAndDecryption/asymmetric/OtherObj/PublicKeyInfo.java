package lich.tool.encryptionAndDecryption.asymmetric.OtherObj;

import java.math.BigInteger;
import java.util.Date;

/**
 * 公钥证书信息
 * @author liuch
 *
 */
public class PublicKeyInfo {
	/**
	 * sn
	 */
	private BigInteger serial=BigInteger.valueOf(System.currentTimeMillis());
	/**
	 * 有效期开始
	 */
	private Date notBefore;
	/**
	 * 有效期结束
	 */
	private Date notAfter; 
	/**
	 * dn
	 */
	private String subject;
	
	/**
	 * 签名算法
	 */
	private String signatureAlgorithm;
	
	private  PublicKeyInfo() {
	}
	
	public PublicKeyInfo(Date notBefore, Date notAfter, String subject) {
		super();
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.subject = subject;
	}
	public PublicKeyInfo(BigInteger serial, Date notBefore, Date notAfter, String subject) {
		super();
		this.serial = serial;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.subject = subject;
	}
	
	public PublicKeyInfo(BigInteger serial, Date notBefore, Date notAfter, String subject, String signatureAlgorithm) {
		super();
		this.serial = serial;
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.subject = subject;
		this.signatureAlgorithm = signatureAlgorithm;
	}
	public BigInteger getSerial() {
		return serial;
	}
	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}
	public Date getNotBefore() {
		return notBefore;
	}
	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}
	public Date getNotAfter() {
		return notAfter;
	}
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	
}
