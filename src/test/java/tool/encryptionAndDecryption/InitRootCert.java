package tool.encryptionAndDecryption;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.operator.OperatorCreationException;

import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.PublicKeyInfo;
import lich.tool.encryptionAndDecryption.core.Base;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;

public class InitRootCert {
	public static void main(String[] args) throws ParseException, CertificateEncodingException, OperatorCreationException, CertificateException, IOException {
		Date begin=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2021-01-01 00:00:00");
		Date end=	new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2035-12-31 23:59:59");
		PublicKeyInfo publicKeyInfo=new PublicKeyInfo(begin, end, "C=CN , CN=lich");
		System.out.println("GM:"+org.apache.commons.codec.binary.Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo, Base.getRootGMX509Certificate().getPublicKey()).getEncoded()));
		System.out.println("RSA:"+org.apache.commons.codec.binary.Base64.encodeBase64String(PublicKeyTool.getX509Certificate(publicKeyInfo, Base.getRootGMX509Certificate().getPublicKey()).getEncoded()));
		
	}
}
