package com.cmcc.aqb.enc.dec;

import com.google.common.base.Charsets;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

/**
 * ClassName:Sha <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午10:49:12 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class Sha {

	private static HashFunction sha1 = Hashing.sha1();
	private static HashFunction sha256 = Hashing.sha256();
	private static HashFunction sha512 = Hashing.sha512();
	

	/**
	 * 
	 * getSha1:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param str
	 * @return
	 * @since JDK 1.6
	 */
	public static String getSha1(String str) {
		return sha1.newHasher().putString(str, Charsets.UTF_8).hash().toString();
	}

	/**
	 * 
	 * getSha256:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param str
	 * @return
	 * @since JDK 1.6
	 */
	public static String getSha256(String str) {
		return sha256.newHasher().putString(str, Charsets.UTF_8).hash().toString();
	}

	/**
	 * 
	 * getSha512:(). <br/>
	 * 
	 * 
	 * @author chiwei
	 * @param str
	 * @return
	 * @since JDK 1.6
	 */
	public static String getSha512(String str) {
		return sha512.newHasher().putString(str, Charsets.UTF_8).hash().toString();
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println(getSha1("123"));
		System.out.println(getSha256("123"));
		System.out.println(getSha512("123"));
	}

}
