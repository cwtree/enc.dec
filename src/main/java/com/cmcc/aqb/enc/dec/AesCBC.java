package com.cmcc.aqb.enc.dec;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

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
public class AesCBC {

    private final static String KEY_ALGO = "AES";
    private final static String ALGO = "AES/CBC/PKCS5Padding";

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
    public static byte[] decByAes(byte[] data, String key, String ivParam) throws Exception {
        SecretKey deskey = new SecretKeySpec(Base64.decodeBase64(key), KEY_ALGO);
        Cipher cipher = Cipher.getInstance(ALGO);
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivParam));
        cipher.init(Cipher.DECRYPT_MODE, deskey, iv);
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
    public static byte[] encByAes(byte[] data, String key, String ivParam) throws Exception {
        SecretKey deskey = new SecretKeySpec(Base64.decodeBase64(key), KEY_ALGO);
        Cipher cipher = Cipher.getInstance(ALGO);
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivParam));
        cipher.init(Cipher.ENCRYPT_MODE, deskey, iv);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        // TODO Auto-generated method stub
        // 长度16，24，32字节
        String AES_KEY = "O2KCeMuWTsO+KAEI8tl3IA==";//genKey();
        String ivParam = "k/GKAF24LfiVddp68ceFVA==";//genKey();
        String word = "eae6b5fdd747ac2a0822304964ae73f8e8e589af50eca3e3789ea755baf7b6698c526e6b33f82a134e529b871909783fea59033e300c92a1973cc5f6850243cd1be7e56cbd9ac6a71e9cb163fdac195414500f20d4a21ee567ff6b66cce0c694";
        //
        Hex.decodeHex(word.toCharArray());
        System.out.println("解密后：" + new String(
                decByAes(Hex.decodeHex(word.toCharArray()), AES_KEY, ivParam), "UTF-8"));
        System.out.println("解密后：" + Hex
                .encodeHexString(decByAes(Hex.decodeHex(word.toCharArray()), AES_KEY, ivParam)));

        /**System.out.println("AES密钥:" + AES_KEY);
        System.out.println("IV向量:" + ivParam);
        System.out.println("AES密钥字节长度:" + Base64.decodeBase64(AES_KEY).length);
        byte[] bytes = encByAes(word.getBytes(), AES_KEY, ivParam);
        System.out.println("--" + bytes.length);
        System.out.println(Hex.encodeHexString(bytes));
        System.out.println("--" + Base64.encodeBase64String(bytes));
        String encWord = new String(bytes);
        System.out.println("加密后：" + encWord);
        System.out.println("解密后：" + new String(decByAes(bytes, AES_KEY, ivParam)));
        //a2725cb331a8195802bbeafadd3122a264ffc1ba3688b8c299ec19e7cb58422
        **/
        System.out.println();
    }
}
