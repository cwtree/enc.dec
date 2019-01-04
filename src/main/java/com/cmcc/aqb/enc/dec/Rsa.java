package com.cmcc.aqb.enc.dec;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * ClassName:Rsa <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午11:25:04 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class Rsa {

	/**
	 * 加密算法RSA
	 */
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * 签名算法
	 */
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	/**
	 * 获取公钥的key
	 */
	private static final String PUBLIC_KEY = "RSAPublicKey";

	private static final int KEY_LEN = 1024;// 密钥长度

	/**
	 * 获取私钥的key
	 */
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * RSA最大加密明文大小
	 */
	private static final int MAX_ENCRYPT_BLOCK = KEY_LEN / 8 - 11;

	/**
	 * RSA最大解密密文大小
	 */
	private static final int MAX_DECRYPT_BLOCK = KEY_LEN / 8;

	private static final Provider DEFAULT_PROVIDER = new BouncyCastleProvider();
	private static KeyPairGenerator keyPairGen = null;
	private static KeyFactory keyFactory = null;
	private static KeyPair keyPair = null;

	static {
		try {
			keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, DEFAULT_PROVIDER);
			keyFactory = KeyFactory.getInstance(KEY_ALGORITHM, DEFAULT_PROVIDER);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * genKeyPair:(). <br/>
	 * 
	 * 生成公司钥对，返回的是经过BASE64编码的密钥
	 * 
	 * @author chiwei
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static synchronized KeyPair genKeyPair() throws Exception {
		keyPairGen.initialize(KEY_LEN, new SecureRandom());
		keyPair = keyPairGen.generateKeyPair();
		return keyPair;
	}

	/**
	 * 
	 * genKeyPair:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static Map<String, String> genStrKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(KEY_LEN);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, String> keyMap = new HashMap<String, String>(2);
		keyMap.put(PUBLIC_KEY, Base64.encodeBase64String(publicKey.getEncoded()));
		keyMap.put(PRIVATE_KEY, Base64.encodeBase64String(privateKey.getEncoded()));
		return keyMap;
	}

	/**
	 * 
	 * genPublicKey:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param modulus
	 * @param publicExponent
	 * @return
	 * @since JDK 1.6
	 */
	public static RSAPublicKey genPublicKey(byte[] modulus, byte[] publicExponent) {
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus),
				new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * genPrivateKey:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param modulus
	 * @param privateExponent
	 * @return
	 * @since JDK 1.6
	 */
	public static RSAPrivateKey genPrivateKey(byte[] modulus, byte[] privateExponent) {
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus),
				new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * sign:(). <br/>
	 * 
	 * 用私钥进行签名，返回BASE64编码的内容
	 * 
	 * @author chiwei
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateK);
		signature.update(data);
		return Base64.encodeBase64String(signature.sign());
	}

	/**
	 * 
	 * verify:(). <br/>
	 * 
	 * 用公钥对签名进行验证
	 * 
	 * @author chiwei
	 * @param data
	 * @param publicKey
	 * @param sign
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicK = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicK);
		signature.update(data);
		return signature.verify(Base64.decodeBase64(sign));
	}

	/**
	 * 使用指定的公钥加密数据。
	 * 
	 * @param publicKey
	 *            给定的公钥。
	 * @param data
	 *            要加密的数据。
	 * @return 加密后的数据。
	 */
	public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(KEY_ALGORITHM);
		ci.init(Cipher.ENCRYPT_MODE, publicKey);
		return ci.doFinal(data);
	}

	/**
	 * 使用指定的私钥解密数据。
	 * 
	 * @param privateKey
	 *            给定的私钥。
	 * @param data
	 *            要解密的数据。
	 * @return 原数据。
	 */
	public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(KEY_ALGORITHM);
		ci.init(Cipher.DECRYPT_MODE, privateKey);
		return ci.doFinal(data);
	}

	/**
	 * 
	 * decryptByPrivateKey:(). <br/>
	 * 
	 * 私钥解密
	 * 
	 * @author chiwei
	 * @param encryptedData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
			throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 
	 * decryptByPublicKey:(). <br/>
	 * 
	 * 公钥解密
	 * 
	 * @author chiwei
	 * @param encryptedData
	 * @param publicKey
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
			throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 
	 * encryptByPublicKey:(). <br/>
	 * 
	 * 公钥加密
	 * 
	 * @author chiwei
	 * @param data
	 * @param publicKey
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	/**
	 * 
	 * encryptByPrivateKey:(). <br/>
	 * 
	 * 私钥加密
	 * 
	 * @author chiwei
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		byte[] enBy = null;
		keyPair = genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		String data = "123";
		enBy = encrypt(publicKey, data.getBytes());
		System.out.println(Base64.encodeBase64String(enBy));
		System.out.println(new String(decrypt(privateKey, enBy)));
	}

}
