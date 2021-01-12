package lich.tool.encryptionAndDecryption;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;
/**
 * 支持算法合集
 * @author liuch
 *
 */
public class ProviderMode {
	public static class MessageDigest{
		public static final String MD2="MD2";
		public static final String MD4="MD4";
		public static final String MD5="MD5";
		public static final String SHA1="SHA1";
		public static final String SHA224="SHA224";	
		public static final String SHA256="SHA256";
		public static final String SHA384="SHA384";
		public static final String SHA512="SHA512";
		public static final String SHA3_224="SHA3-224";
		public static final String SHA3_256="SHA3-256";
		public static final String SHA3_384="SHA3-384";
		public static final String SHA3_512="SHA3-512";
		public static final String SM3="SM3";	
	}
	
	public static class Symmetric{
		public enum Cipher{	
			SM4_CBC_NOPadding("SM4/CBC/NOPadding","SM4"),
			SM4_CBC_PKCS5Padding("SM4/CBC/PKCS5Padding","SM4"),
			SM4_CBC_PKCS7Padding("SM4/CBC/PKCS7Padding","SM4"),
			SM4_ECB_NOPadding("SM4/ECB/NOPadding","SM4"),
			SM4_ECB_PKCS5Padding("SM4/ECB/PKCS5Padding","SM4"),
			SM4_ECB_PKCS7Padding("SM4/ECB/PKCS7Padding","SM4"),
			
			AES_ECB_PKCS7Padding("AES/ECB/PKCS7Padding","AES"),
			AES_ECB_PKCS5Padding("AES/ECB/PKCS5Padding","AES"),
			AES_ECB_NOPadding("AES/ECB/NOPadding","AES"),
			AES_CBC_PKCS7Padding("AES/CBC/PKCS7Padding","AES"),
			AES_CBC_PKCS5Padding("AES/CBC/PKCS5Padding","AES"),
			AES_CBC_NOPadding("AES/CBC/NOPadding","AES"),
			
			DES_ECB_PKCS7Padding("DES/ECB/PKCS7Padding","DES"),
			DES_ECB_PKCS5Padding("DES/ECB/PKCS5Padding","DES"),
			DES_ECB_NOPadding("DES/ECB/NOPadding","DES"),
			DES_CBC_PKCS7Padding("DES/CBC/PKCS7Padding","DES"),
			DES_CBC_PKCS5Padding("DES/CBC/PKCS5Padding","DES"),
			DES_CBC_NOPadding("DES/CBC/NOPadding","DES"),
			
			
			DESede_ECB_PKCS7Padding("DESede/ECB/PKCS7Padding","DESede"),
			DESede_ECB_PKCS5Padding("DESede/ECB/PKCS5Padding","DESede"),
			DESede_ECB_NOPadding("DESede/ECB/NOPadding","DESede"),
			DESede_CBC_PKCS7Padding("DESede/CBC/PKCS7Padding","DESede"),
			DESede_CBC_PKCS5Padding("DESede/CBC/PKCS5Padding","DESede"),
			DESede_CBC_NOPadding("DESede/CBC/NOPadding","DESede");
			
			private  Cipher(String algorithm,String keyType) {
				this.algorithm=algorithm;
				this.keyType=keyType;
			}
			private String algorithm;
			private String keyType;
			public String getAlgorithm() {
				return algorithm;
			}
			public String getKeyType() {
				return keyType;
			}
		}
	}
	public static class Asymmetric{
		public static class KeyStore{
			public static String PKCS12="pkcs12";
		}
		public static class RSA{	
			
			public static class KeyPairGenerator{
				public static String RSA="RSA";
				public static String RSASSA_PSS="RSASSA_PSS";
				
			}
			public static class  Signature{
				public static String DEFAULT="SHA1WithRSA";	
				public static String RSASSA_PSS="RSASSA-PSS";
				public static String RAWRSASSA_PSS="RAWRSASSA-PSS";	
				public static String SHA1WithRSA="SHA1WithRSA";	
				public static String SHA224WithRSA="SHA224WithRSA";	
				public static String SHA256WithRSA="SHA256WithRSA";
				public static String SHA384WithRSA="SHA384WithRSA";
				public static String SHA512WithRSA="SHA512WithRSA";
				public static String SHA3_224WithRSA="SHA3-224WithRSA";
				public static String SHA3_256WithRSA="SHA3-256WithRSA";
				public static String SHA3_384WithRSA="SHA3-384WithRSA";
				public static String SHA3_512WithRSA="SHA3-512WithRSA";
			}
			public static class  Cipher{
				public static String RSA="RSA";
				//public static String RSA_RAW="RSA/RAW";
				//public static String RSA_CBC_NOPADDING="RSA/CBC/NOPadding";
				public static String RSA_ECB_NOPADDING="RSA/ECB/NOPadding";
				public static String RSA_ECB_PKCS1PADDING="RSA/ECB/PKCS1Padding";
				//public static String RSA_ECB_PKCS5PADDING="RSA/ECB/PKCS5Padding";
				//public static String RSA_1="RSA/1";
				//public static String RSA_2="RSA_2";
				//public static String RSA_OAEP="RSA/OAEP";
				//public static String RSA_ISO9796_1="RSA/ISO9796-1";
			}
		};
		public static class GM {
			public static class KeyPairGenerator{
				public static String  EC="EC";
			}
			public static class  Signature{
				public static String DEFAULT="SM3WITHSM2";	
				public static String  SHA256WITHSM2="SHA256WITHSM2";
				public static String  SM3WITHSM2="SM3WITHSM2";
				
			}
			public static class  Cipher {
			
				public static String SM2="SM2";
				public static String SM2WITHSM3="SM2WITHSM3";
				public static String SM2WITHBLAKE2B="SM2WITHBLAKE2B";
				public static String SM2WITHBLAKE2S="SM2WITHBLAKE2S";
				public static String SM2WITHWHIRLPOOL="SM2WITHWHIRLPOOL";
				public static String SM2WITHMD5="SM2WITHMD5";
				public static String SM2WITHRIPEMD160="SM2WITHRIPEMD160";
				public static String SM2WITHSHA1="SM2WITHSHA1";
				public static String SM2WITHSHA224="SM2WITHSHA224";
				public static String SM2WITHSHA256="SM2WITHSHA256";
				public static String SM2WITHSHA384="SM2WITHSHA384";
				public static String SM2WITHSHA512="SM2WITHSHA512";
				
			}
			
		}
	}
	
	public static class Check{
		private static Map<String,Set<String>> values=new ConcurrentHashMap<String, Set<String>>();
		public static boolean contains(Class o,String s) {
				String	on=o.getName();
				if(values.containsKey(on)) {
					return values.get(on).contains(s.toUpperCase());
				}else {
					try {
						synchronized (values) {
							Set<String> ss=	new ConcurrentSkipListSet();
							Field[] fields = o.getDeclaredFields();
							for(Field field: fields)ss.add(((String)field.get(null)).toUpperCase());	
							values.put(on,ss);
							return values.get(on).contains(s.toUpperCase());
						}
					} catch (Exception e) {
						e.printStackTrace();
						return false;
					}
					
				}	
		}
	}
	
}
