package com.cmcc.aqb.enc.dec;

import com.google.common.base.Charsets;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

/**
 * ClassName:Md5 <br/>
 * Function: TODO ADD FUNCTION. <br/>
 * Reason: TODO ADD REASON. <br/>
 * Date: 2016年10月11日 上午10:47:04 <br/>
 * 
 * @author chiwei
 * @version
 * @since JDK 1.6
 * @see
 */
public class Md5 {

	private static HashFunction hf = Hashing.md5();

	/**
	 * 
	 * getMd5:(); Description:TODO
	 * 
	 * @author chiwei
	 * @param str
	 * @return
	 * @since JDK 1.6
	 */
	public static String getMd5(String str) {
		return hf.newHasher().putString(str, Charsets.UTF_8).hash().toString();
	}

	/**
	 * 
	 * @param bb
	 * @return
	 */
	public static String getMd5(byte[] bb) {
		return hf.newHasher().putBytes(bb).hash().toString();
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println(getMd5("123"));
		System.out.println(getMd5("123".getBytes()));
	}

}
