package tool.encryptionAndDecryption;


import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;

import lich.tool.encryptionAndDecryption.core.Base;
import lich.tool.encryptionAndDecryption.core.asymmetric.AsymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.KeyStoreTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PrivateKeyTool;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;
import lich.tool.encryptionAndDecryption.asymmetric.OtherObj.P12Data;

public class TestKeyStore {
	 
	@Test
	public void TestRSA() throws Exception, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException{
		byte [] p12=Base64.decodeBase64("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");
    	
    	P12Data k=KeyStoreTool.loadPKCS12(p12, "123456");
    	X509Certificate cert=(X509Certificate)k.getCert();
    	PublicKey publicKey=cert.getPublicKey();
    	PrivateKey privateKey=k.getPrivateKey();
    	byte[] ori="测试原文".getBytes("utf-8");
    	byte[]  sign= AsymmetricTool.sign(ori, privateKey,cert);
    	//sign= AsymmetricTool.sign(ori.getBytes("utf-8"), privateKey, Provider.RSA.Signature.SHA256WithRSA);
    	System.out.println("sign:"+Base64.encodeBase64String(sign));
    	System.out.println("verify:"+AsymmetricTool.verify(sign, ori,cert));
    	System.out.println("verify:"+AsymmetricTool.verify(sign, ori, publicKey,ProviderMode.Asymmetric.RSA.Signature.SHA256WithRSA));
    	ori="加密原文".getBytes("utf-8");
    	byte [] enc=AsymmetricTool.encrypt(ori, publicKey, ProviderMode.Asymmetric.RSA.Cipher.RSA);
    	System.out.println("enc:"+Base64.encodeBase64String(enc));
    	System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, privateKey, ProviderMode.Asymmetric.RSA.Cipher.RSA),"utf-8"));
	}
	@Test
	public void TestSM2() throws Exception {
		/**************发送CA数据***************/
		String signKey=	Base64.encodeBase64String(PublicKeyTool.getPublicKeyByte(Base.getRootGMX509Certificate().getPublicKey()));
		/**************CA返回数据***************/
		String	signKeyCert="MIIDvTCCA2GgAwIBAgIIaeMAmgAlWT0wDAYIKoEcz1UBg3UFADB2MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVpMSYwJAYDVQQKDB1Bbkh1aSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTENMAsGA1UECwwEQUhDQTEQMA4GA1UEAwwHQUhDQVNNMjAeFw0yMTAxMDQwODA3NDJaFw0yMzAxMDQwODA3NDJaMCsxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEHskcZtdrXttC6SkRTpUojOXQ63A7X23E3gjXrc3h9+1QE2Lv1jN1quL57299kQjC6rqxnwmMeGqlly9dVZ/3RqOCAiAwggIcMAwGA1UdEwQFMAMBAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAsGA1UdDwQEAwIAwDAfBgNVHSMEGDAWgBRGmbxhYuK6U6kMiNLNXZbAyDC6zzCBygYDVR0fBIHCMIG/MIG8oIG5oIG2hoGObGRhcDovL2xkYXAuYWhlY2EuY246Mzg5L0NOPUFIQ0FTTTIsQ049QUhDQVNNMiwgT1U9Q1JMRGlzdHJpYnV0ZVBvaW50cywgbz1haGNhP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIYjaHR0cDovL3d3dy5haGVjYS5jbi9jcmwvQUhDQVNNMi5jcmwwgdIGCCsGAQUFBwEBBIHFMIHCMIGLBggrBgEFBQcwAoZ/bGRhcDovL2xkYXAuYWhlY2EuY246Mzg5L0NOPUFIQ0FTTTIsQ049QUhDQVNNMiwgT1U9Y0FDZXJ0aWZpY2F0ZXMsIG89YWhjYT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAyBggrBgEFBQcwAoYmaHR0cDovL3d3dy5haGVjYS5jbi9jYWNlcnQvQUhDQVNNMi5jZXIwHQYDVR0OBBYEFFUmX9QRaIYPflfrIEwmc6+T8rSsMAwGCCqBHM9VAYN1BQADSAAwRQIhAMYenjVG/2YUhD1shHBhiBDrHG1q4sTSEiZ1zZ1GFOZRAiAwwhRCpoHtfdnQbdEVZubbK/Oz8+YoQnWFG2DGjLFSEA==";
		String  encKeyCert="MIIDszCCA1egAwIBAgIIaeMAfgAlWTwwDAYIKoEcz1UBg3UFADB2MQswCQYDVQQGEwJDTjEOMAwGA1UECAwFQW5IdWkxDjAMBgNVBAcMBUhlRmVpMSYwJAYDVQQKDB1Bbkh1aSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTENMAsGA1UECwwEQUhDQTEQMA4GA1UEAwwHQUhDQVNNMjAeFw0yMTAxMDQwODA3NDJaFw0yMzAxMDQwODA3NDJaMCsxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBKuHb+za3UnC989VEWZ7vPv9yZeZj0L4x0pVJtUyKfLC7TBCsGxviADKvpyrCUPHKpkr2feL5/tjLfEPBTZeoaOCAhYwggISMAwGA1UdEwQFMAMBAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwCwYDVR0PBAQDAgAwMB8GA1UdIwQYMBaAFEaZvGFi4rpTqQyI0s1dlsDIMLrPMIHKBgNVHR8EgcIwgb8wgbyggbmggbaGgY5sZGFwOi8vbGRhcC5haGVjYS5jbjozODkvQ049QUhDQVNNMixDTj1BSENBU00yLCBPVT1DUkxEaXN0cmlidXRlUG9pbnRzLCBvPWFoY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hiNodHRwOi8vd3d3LmFoZWNhLmNuL2NybC9BSENBU00yLmNybDCB0gYIKwYBBQUHAQEEgcUwgcIwgYsGCCsGAQUFBzAChn9sZGFwOi8vbGRhcC5haGVjYS5jbjozODkvQ049QUhDQVNNMixDTj1BSENBU00yLCBPVT1jQUNlcnRpZmljYXRlcywgbz1haGNhP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MDIGCCsGAQUFBzAChiZodHRwOi8vd3d3LmFoZWNhLmNuL2NhY2VydC9BSENBU00yLmNlcjAdBgNVHQ4EFgQUoYGcKEuC2bCcA1fA4yNOMDgxyF4wDAYIKoEcz1UBg3UFAANIADBFAiEA1ft9BCho5QC3iJgu25eyV9I6VVe1zMaH0Grbbfz7cV4CIC+Xo7Tf7gakzDHqKeRaFxJfRXG+YwVF7+O8IIv4RysY";	
		String encKeyProtection="AQAAAAEEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADpP5zcN19xOUNSQQJ+UwfUUJYxw2PfPxMN9JgsUm0qCQABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASrh2/s2t1JwvfPVRFme7z7/cmXmY9C+MdKVSbVMinyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADC7TBCsGxviADKvpyrCUPHKpkr2feL5/tjLfEPBTZeoQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAocuNU15U9QhNzasMrllYeTC5+ocIXanU4/2BK0XeYwkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAawWjtJAUzoOLgsgcyaWZdikDxakN1qKyx3kkEdBOH+wi2yU1jjbGO2Fq8rZtY0ILinbzovrZAhLLDh5UYaMzQQAAAAxr22PeNfWLd0J8A8BdNRew==";
		
		String decKeyProtection=Base64.encodeBase64String(PrivateKeyTool.toEnvelopedKeyBlobByGMPrivateKey(Base.getRootGMPrivateKey()));
		PrivateKey  prkSign=PrivateKeyTool.toGMPrivateKeyByEnvelopedKeyBlob(Base64.decodeBase64(decKeyProtection));
		PrivateKey  prkEnc=PrivateKeyTool.toGMPrivateKeyByEnvelopedKeyBlob(Base64.decodeBase64(encKeyProtection));
		
		Certificate	certificateSignKey=PublicKeyTool.loadX509Certificate(Base64.decodeBase64(signKeyCert));
		Certificate	certificateEncKey=PublicKeyTool.loadX509Certificate(Base64.decodeBase64(encKeyCert));
		byte[] ori="测试原文".getBytes("utf-8");
		System.out.println("-----------签名证书测试-----------");
		byte[]  sign= AsymmetricTool.sign(ori, prkSign, (X509Certificate)certificateSignKey);
		System.out.println("sign:"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori, (X509Certificate)certificateSignKey));
		ori="加密原文".getBytes("utf-8");
	
		byte [] enc=AsymmetricTool.encrypt(ori, certificateSignKey.getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println("enc:"+Base64.encodeBase64String(enc));
		System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, prkSign, ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
		
		System.out.println("-----------加密签名证书测试-----------");
		sign= AsymmetricTool.sign(ori, prkEnc, (X509Certificate)certificateEncKey);
		System.out.println("sign:"+Base64.encodeBase64String(sign));
		System.out.println("verify:"+AsymmetricTool.verify(sign, ori, (X509Certificate)certificateEncKey));
		ori="加密原文".getBytes("utf-8");
		enc=AsymmetricTool.encrypt(ori, certificateEncKey.getPublicKey(),ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println("enc:"+Base64.encodeBase64String(enc));
		System.out.println("ori:"+new String(AsymmetricTool.decrypt(enc, prkEnc, ProviderMode.Asymmetric.GM.Cipher.SM2),"utf-8"));
	}
	@Test
	public void a() throws Exception {
		String a="MIICFjCCAbygAwIBAgIJAcDZarzRpOD3MAoGCCqBHM9VAYN1MEQxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZjb20uZGoxDzANBgNVBAsMBmNvbS5kajETMBEGA1UEAwwKREogUm9vdCBDQTAeFw0yMTA1MTkwMjA0MDJaFw00MTA1MTQwMjA0MDJaMEIxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZjb20uZGoxDzANBgNVBAsMBmNvbS5kajERMA8GA1UEAwwIbmV0X3NpZ24wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASz8DPs+tn6C4ap8Ui+UmnV5ujo7QYVu4WXqS32Dpr9H1RmfAH54b5+MxcdgtcXvfMRqDyj/ox8+KZnmrWJ2ci8o4GYMIGVMB0GA1UdDgQWBBSZSNa6Tnay0BeM+9LqKyVrp70BhjAfBgNVHSMEGDAWgBRWwvXCFVEO9Pt54OoL4vTrJ39WYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIDuDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwEwYDVR0RBAwwCoIIbmV0X3NpZ24wCgYIKoEcz1UBg3UDSAAwRQIhAIL3iaobH5nkEVWRL5VObrCGtWTd4vJK/ifeO6HFuHvWAiAY1PxmuvXh3V+D/6e4FtxEpirNtPR9yfaCSz33l4j3tQ==";
		byte [] b= {0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04};
		
		X509Certificate loadX509Certificate = PublicKeyTool.loadX509Certificate(Base64.decodeBase64(a));
		//byte [] enc=AsymmetricTool.encrypt(b, loadX509Certificate.getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		//enc=AsymmetricTool.SM2CipherTOGMC1C3C2(enc);
		//System.out.println(Base64.encodeBase64String(enc));;
		//enc=AsymmetricTool.GMC1C3C2TOSM2Cipher(enc);
		byte [] enc=Base64.decodeBase64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIEw5Stev/FMaw7m9jiVFjj3Q41iwXYNLb/ZuYndY/ywAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkwsDD7KNwsWbZUm85luOxs0aZK5GicDa1LMRFh+84fttjf2MCqEcfXBhCcUOx2v3UuuxnGadjwxApryi9e/kWxAAAACp4hC92uMey3kuXKl9QRyk");
		enc=AsymmetricTool.GMC1C3C2TOSM2Cipher(enc);
		byte [] bx=Base64.decodeBase64("QA+zBn7evET/BQYG3Y7TxgKPhPAia6dMiofs81qbCn0=");
		
		PrivateKey prk=	PrivateKeyTool.toGMPrivateKey(bx,((BCECPublicKey) loadX509Certificate.getPublicKey()).getQ().getEncoded(false));
	    byte[] bxx=	AsymmetricTool.decrypt(enc, prk, ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println(Arrays.toString(bxx));
		String src = "123123123666777888";
		System.out.println(src.getBytes().length);
		
	}
}
