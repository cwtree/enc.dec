package com.cmcc.aqb.enc.dec;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * ClassName:Aes <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午11:13:37 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class AesECB {

    private final static String KEY_ALGO = "AES";
    private final static String ALGO = "AES/ECB/PKCS5Padding";

    private static final Random r = new Random();

    public static String genKey() throws Exception {
        byte[] b = new byte[16];
        r.nextBytes(b);
        return Base64.encodeBase64String(b);
    }

    /**
     * 
     * decByAes:(). <br/>
     * 
     * 
     * @author chiwei
     * @param data
     * @return
     * @throws Exception
     * @since JDK 1.6
     */
    public static byte[] decByAes(byte[] data, String key) throws Exception {
        SecretKey deskey = new SecretKeySpec(Base64.decodeBase64(key), KEY_ALGO);
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.DECRYPT_MODE, deskey);
        return cipher.doFinal(data);
    }

    /**
     * 
     * encByAes:(). <br/>
     * 
     * 
     * @author chiwei
     * @param data
     * @return
     * @throws Exception
     * @since JDK 1.6
     */
    public static byte[] encByAes(byte[] data, String key) throws Exception {
        SecretKey deskey = new SecretKeySpec(Base64.decodeBase64(key), KEY_ALGO);
        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, deskey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        // TODO Auto-generated method stub
        // 长度16，24，32字节
        String AES_KEY = "O2KCeMuWTsO+KAEI8tl3IA==";//genKey();
        String word = "hello";
        byte[] enc = encByAes(word.getBytes(), AES_KEY);
        System.out.println("解密后：" + new String(decByAes(enc, AES_KEY), "UTF-8"));

        System.out.println();
    }
}
