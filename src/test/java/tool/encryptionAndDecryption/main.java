package tool.encryptionAndDecryption;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import lich.tool.encryptionAndDecryption.EncryptionAndDecryptionException;
import lich.tool.encryptionAndDecryption.ProviderMode;
import lich.tool.encryptionAndDecryption.core.asymmetric.AsymmetricTool;
import lich.tool.encryptionAndDecryption.core.asymmetric.PublicKeyTool;

public class main {
	public static void main(String[] args) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, EncryptionAndDecryptionException {
		String a="MIICFjCCAbygAwIBAgIJAcDZarzRpOD3MAoGCCqBHM9VAYN1MEQxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZjb20uZGoxDzANBgNVBAsMBmNvbS5kajETMBEGA1UEAwwKREogUm9vdCBDQTAeFw0yMTA1MTkwMjA0MDJaFw00MTA1MTQwMjA0MDJaMEIxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZjb20uZGoxDzANBgNVBAsMBmNvbS5kajERMA8GA1UEAwwIbmV0X3NpZ24wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASz8DPs+tn6C4ap8Ui+UmnV5ujo7QYVu4WXqS32Dpr9H1RmfAH54b5+MxcdgtcXvfMRqDyj/ox8+KZnmrWJ2ci8o4GYMIGVMB0GA1UdDgQWBBSZSNa6Tnay0BeM+9LqKyVrp70BhjAfBgNVHSMEGDAWgBRWwvXCFVEO9Pt54OoL4vTrJ39WYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIDuDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwEwYDVR0RBAwwCoIIbmV0X3NpZ24wCgYIKoEcz1UBg3UDSAAwRQIhAIL3iaobH5nkEVWRL5VObrCGtWTd4vJK/ifeO6HFuHvWAiAY1PxmuvXh3V+D/6e4FtxEpirNtPR9yfaCSz33l4j3tQ==";
		byte [] b= {0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04,
					0x01,0x02,0x03,0x04};
		
		X509Certificate loadX509Certificate = PublicKeyTool.loadX509Certificate(Base64.decodeBase64(a));
		byte [] enc=AsymmetricTool.encrypt(b, loadX509Certificate.getPublicKey(), ProviderMode.Asymmetric.GM.Cipher.SM2);
		System.out.println(Base64.encodeBase64(AsymmetricTool.SM2CipherTOGMC1C3C2(enc)));;
	}
}
