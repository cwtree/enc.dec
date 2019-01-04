package com.cmcc.aqb.enc.dec;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * ClassName:Des <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午11:05:59 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class Des {

	private final static String KEY_DES = "DES";
	private static final String KEY_3_DES = "DESede";

	/**
	 * 
	 * decByDes:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] decByDes(byte[] data, String key) throws Exception {
		// DES算法要求有一个可信任的随机数源
		SecureRandom random = new SecureRandom();
		DESKeySpec desKey = new DESKeySpec(key.getBytes("UTF-8"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DES);
		SecretKey securekey = keyFactory.generateSecret(desKey);
		Cipher cipher = Cipher.getInstance(KEY_DES);
		cipher.init(Cipher.DECRYPT_MODE, securekey, random);
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * encByDes:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] encByDes(byte[] data, String key) throws Exception {
		DESKeySpec desKey = new DESKeySpec(key.getBytes("UTF-8"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DES);
		SecretKey securekey = keyFactory.generateSecret(desKey);
		Cipher cipher = Cipher.getInstance(KEY_DES);
		cipher.init(Cipher.ENCRYPT_MODE, securekey);
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * decBy3Des:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] decBy3Des(byte[] data, String key) throws Exception {
		Cipher cipher = Cipher.getInstance(KEY_3_DES);
		DESedeKeySpec dks = new DESedeKeySpec(Base64.decodeBase64(key));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_3_DES);
		SecretKey secretKey = keyFactory.generateSecret(dks);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * encBy3Des:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static byte[] encBy3Des(byte[] data, String key) throws Exception {
		Cipher cipher = Cipher.getInstance(KEY_3_DES);
		DESedeKeySpec dks = new DESedeKeySpec(Base64.decodeBase64(key));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_3_DES);
		SecretKey secretKey = keyFactory.generateSecret(dks);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}

	public static String genDesKey() {
		try {
			KeyGenerator kg = KeyGenerator.getInstance(KEY_DES);
			kg.init(56);// 64位，8字节，56位密钥，8位奇偶校验，每8位有一位奇偶校验位
			SecretKey secretKey = kg.generateKey();
			byte[] keyBy = secretKey.getEncoded();
			return Base64.encodeBase64String(keyBy);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String gen3DesKey() {
		try {
			KeyGenerator kg = KeyGenerator.getInstance(KEY_3_DES);
			kg.init(168);// 192位，24字节，168位密钥，24位奇偶校验，每8位有一位奇偶校验位
			SecretKey secretKey = kg.generateKey();
			byte[] keyBy = secretKey.getEncoded();
			return Base64.encodeBase64String(keyBy);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) throws Exception {
		// 长度8字节
		String DES_KEY = genDesKey();
		// 长度24字节
		String DES_3_KEY = gen3DesKey();
		System.out.println("DES密钥:\n" + DES_KEY);
		System.out.println("DES密钥字节长度:\n" + DES_KEY.getBytes("UTF-8").length);
		String word = "123";
		System.out.println("原文：" + word);
		System.out.println("=============DES=============");
		byte b[] = encByDes(word.getBytes("UTF-8"), DES_KEY);
		String encWord = new String(b);
		System.out.println("加密后：" + encWord);
		System.out.println("解密后：" + new String(decByDes(b, DES_KEY)));
		System.out.println("=============3DES=============");
		System.out.println("3DES密钥:" + DES_3_KEY);
		System.out.println("3DES密钥字节长度:" + DES_3_KEY.getBytes().length);
		b = encBy3Des(word.getBytes(), DES_3_KEY);
		encWord = new String(b);
		System.out.println("加密后：" + encWord);
		System.out.println("解密后：" + new String(decBy3Des(b, DES_3_KEY)));
	}

}
