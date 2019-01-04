package com.cmcc.aqb.enc.dec;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

/**
 * ClassName:Hmac <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午10:52:42 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class HmacSHA1 {

	private final static String ALGO = "HmacSHA1";

	/**
	 * 
	 * getKey:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @return
	 * @since JDK 1.6
	 */
	public static String getKey() {
		SecretKey key;
		try {
			KeyGenerator generator = KeyGenerator.getInstance(ALGO);
			key = generator.generateKey();
			return Base64.encodeBase64String(key.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * enc:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @param key
	 * @return
	 * @since JDK 1.6
	 */
	public static byte[] enc(byte[] data, String key) {
		SecretKey secretKey;
		try {
			secretKey = new SecretKeySpec(Base64.decodeBase64(key), ALGO);
			Mac mac = Mac.getInstance(secretKey.getAlgorithm());
			mac.init(secretKey);
			return mac.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 
	 * enc:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 * @since JDK 1.6
	 */
	public static String enc(String data, String key) throws Exception {
		if (StringUtils.isEmpty(data) || StringUtils.isEmpty(data.trim())) {
			return null;
		}
		return Hex.encodeHexString(enc(data.getBytes("UTF-8"), key));
	}

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		String key = getKey();
		System.out.println(key);
		System.out.println(enc("123", key));
	}

}
