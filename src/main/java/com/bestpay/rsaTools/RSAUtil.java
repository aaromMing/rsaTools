package com.bestpay.rsaTools;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;


/**
 * RSA算法
 * 
 * @author 杨双明
 * {@link qq:376043895}
 */
public class RSAUtil {


	public static void main(String[] args) {
		KeyPair keyPair = CipherUtil.rsa_keyPair_generated(1024);
		RSAPrivateCrtKey privateCrtKey=(RSAPrivateCrtKey) keyPair.getPrivate();
		System.out.println(privateCrtKey.getPrimeExponentP());
//		MerchantSysInfo merchantSysInfo = new MerchantSysInfo();
//		merchantSysInfo.setM_rsa_modulu(privateCrtKey.getModulus().toString(16));
//		merchantSysInfo.setM_rsa_pri_p(privateCrtKey.getPrimeP().toString(16));
//		merchantSysInfo.setM_rsa_pri_q(privateCrtKey.getPrimeQ().toString(16));
//		merchantSysInfo.setM_rsa_pri_dp(privateCrtKey.getPrimeExponentP().toString(16));
//		merchantSysInfo.setM_rsa_pri_dq(privateCrtKey.getPrimeExponentQ().toString(16));
//		merchantSysInfo.setM_rsa_pri_qinv(privateCrtKey.getCrtCoefficient().toString(16));
//		merchantSysInfo.setM_rsa_pri_exponent(privateCrtKey.getPrivateExponent().toString(16));

    }
	

	/**
	 * @param reqObj
	 * @return
	 */
	@SuppressWarnings("unchecked")
    public static String getSign(final Object reqObj) {
		if(reqObj == null){
			System.err.println("参数不能为空");
			return null;
		}
		String signStr = null;
		String sign = null;
		try {
			StringBuffer buffer = new StringBuffer();
			ObjectMapper om = new ObjectMapper();
			Map<String, Object> map = om.convertValue(reqObj, Map.class);
			for (Map.Entry<String, Object> maEntry : map.entrySet()) {
				Object val = maEntry.getValue();
				if (val instanceof String[]) {
					maEntry.setValue(Arrays.toString((String[]) val));
				}
				buffer.append(maEntry.getKey()).append("=").append(val)
				        .append("&");
			}
			List<Map.Entry<String, Object>> list = new ArrayList<Map.Entry<String, Object>>(
			        map.entrySet());
			// 排序
			Collections.sort(list, new Comparator<Map.Entry<String, Object>>() {
				public int compare(final Map.Entry<String, Object> o1,
				        final Map.Entry<String, Object> o2) {
					return (o1.getKey()).toString().compareTo(o2.getKey());
				}
			});
			buffer.deleteCharAt(buffer.length()-1);
			signStr = buffer.toString();
			System.out.println("data:"+signStr);
			sign = RSAUtil.rsaPrikeySignature(signStr.getBytes()).toUpperCase();
			System.out.println("sign:"+sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return sign;
	}
	
	public static boolean verifySign(final String data,final String signature) {
		return RSAUtil.rsa_pubkey_verify(data.getBytes(), CipherUtil.decode(signature));
	}
	
	// ===构造两字节，十六进制的数据
	public static String BuildLen(int len) {
		String hex = Integer.toHexString(len);
		if (hex.length() == 1) {
			hex = "000" + hex;
		} else if (hex.length() == 2) {
			hex = "00" + hex;
		} else if (hex.length() == 3) {
			hex = "0" + hex;
		}
		return hex;
	}

	/**
	 * get rsa public key and private key from map return hex data std mode
	 * 
	 * @return map:
	 */
	public static void generate_rsa_std(KeyPair keyPair, Map<String, String> map) {

		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		// public key
		BigInteger public_key_exponent = publicKey.getPublicExponent();
		BigInteger public_key_modules = publicKey.getModulus();
		// output
		map.put(CipherContants.RSA_Name_Public_Modulus,
		        public_key_modules.toString(16));
		map.put(CipherContants.RSA_Name_Public_Exponent,
		        public_key_exponent.toString(16));
		// private key
		BigInteger private_key_modules = privateKey.getModulus();
		BigInteger private_key_exponent = privateKey.getPrivateExponent();
		// output
		map.put(CipherContants.RSA_Name_Private_Modulus,
		        private_key_modules.toString(16));
		map.put(CipherContants.RSA_Name_Private_Exponent,
		        private_key_exponent.toString(16));
	}

	/**
	 * RSAKeySpec init rsa private key crt and rsa private key std and rsa
	 * public key
	 * 
	 * @param type
	 *            【RSA_KeySpec_PubKey =
	 *            1;RSA_KeySpec_PriKey_Std=2;RSA_KeySpec_PriKey_Crt=3;】
	 * @param pri_modulus
	 * @param pri_exponent
	 * @param p
	 * @param q
	 * @param dp
	 * @param dq
	 * @param qinv
	 * @param pub_modulus
	 * @param pub_exponent
	 * @return KeySpec[RSAPublicKeySpec、RSAPrivateCrtKeySpec、RSAPrivateKeySpec]
	 */
	private static KeySpec rsa_init_pk(int type, String pri_modulus,
	        String pri_exponent, String p, String q, String dp, String dq,
	        String qinv, String pub_modulus, String pub_exponent) {

		BigInteger pri_p = null;
		BigInteger pri_q = null;
		BigInteger pri_dp = null;
		BigInteger pri_dq = null;
		BigInteger pri_qinv = null;
		BigInteger pri_exponent_bigInteger = null;
		BigInteger pri_modulus_bigInteger = null;
		BigInteger pub_exponent_bigInteger = null;
		BigInteger pub_modulus_bigInteger = null;
		if (type == CipherContants.RSA_KeyType_PriKey_Crt) {
			// private key crt
			if (dp == null || dq == null || pri_exponent == null
			        || pri_modulus == null || p == null || q == null
			        || qinv == null || pub_exponent == null) {
				return null;
			}
			pri_p = new BigInteger(p, 16);
			pri_q = new BigInteger(q, 16);
			pri_dp = new BigInteger(dp, 16);
			pri_dq = new BigInteger(dq, 16);
			pri_qinv = new BigInteger(qinv, 16);
			pri_exponent_bigInteger = new BigInteger(pri_exponent, 16);
			pri_modulus_bigInteger = new BigInteger(pri_modulus, 16);
			pub_exponent_bigInteger = new BigInteger(pub_exponent, 16);
			RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = new RSAPrivateCrtKeySpec(
			        pri_modulus_bigInteger, pub_exponent_bigInteger,
			        pri_exponent_bigInteger, pri_p, pri_q, pri_dp, pri_dq,
			        pri_qinv);
			return rsaPrivateCrtKeySpec;
		} else if (type == CipherContants.RSA_KeyType_PubKey) {
			// public key
			if (pub_exponent == null || pub_modulus == null) {
				return null;
			}
			pub_exponent_bigInteger = new BigInteger(pub_exponent, 16);
			pub_modulus_bigInteger = new BigInteger(pub_modulus, 16);
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(
			        pub_modulus_bigInteger, pub_exponent_bigInteger);
			return rsaPublicKeySpec;
		} else if (type == CipherContants.RSA_KeyType_PriKey_Std) {
			// private key std
			if (pri_modulus == null || pri_exponent == null) {
				return null;
			}
			pri_exponent_bigInteger = new BigInteger(pri_exponent, 16);
			pri_modulus_bigInteger = new BigInteger(pri_modulus, 16);
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(
			        pri_modulus_bigInteger, pri_exponent_bigInteger);
			return rsaPrivateKeySpec;
		} else {
			return null;
		}
	}

	public static String byteArrayToString(byte[] indata) {

		int g_RespLen = indata.length;
		byte[] g_Response = indata;

		int m = 0;
		String g_InfoString = "";

		while (m < g_RespLen) {
			if ((g_Response[m] & 0xF0) == 0x00) {
				g_InfoString += '0' + Integer
				        .toHexString((short) (0x00FF & g_Response[m]));
			} else {
				g_InfoString += Integer
				        .toHexString((short) (0x00FF & g_Response[m]));
			}
			m++;
		}

		return g_InfoString.toUpperCase();
	}
	
	

	/**
	 * use [rsa private key crt ] or [ras private key std] signature
	 * 
	 * @param data
	 * @param alg
	 *            "SHA1WithRSA"
	 *            SHA1WithRSA、MD2withRSA、MD5withRSA、SHA1withRSA、SHA256withRSA
	 *            、SHA384withRSA、SHA512withRSA
	 * @param prikey_type
	 *            :[RSA_KeyType_PriKey_Std=2] [RSA_KeyType_PriKey_Crt=3]
	 * @param pri_modulus
	 * @param pri_exponent
	 * @param dp
	 * @param dq
	 * @param p
	 * @param q
	 * @param qinv
	 * @param pub_exponents
	 * @return
	 */
	public static String rsaPrikeySignature(byte[] data) {

		String alg = "SHA1WITHRSA";
		int prikey_type = 3;
		String pub_exponet = "010001";
		
		LoadConfigUtil rsaConfig = LoadConfigUtil.getInstance();

		String RSA_MODULU = rsaConfig.getConfigItem("RSA_MODULU");
		String pri_p = rsaConfig.getConfigItem("PRI_P");
		String pri_q = rsaConfig.getConfigItem("PRI_Q");
		String pri_dp = rsaConfig.getConfigItem("PRI_DP");
		String pri_dq = rsaConfig.getConfigItem("PRI_DQ");
		String pri_qinv = rsaConfig.getConfigItem("PRI_QINV");
		String pri_exponet = rsaConfig.getConfigItem("PRI_EXPONET");

		PrivateKey privateKey = null;
		RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = null;// crt
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		rsaPrivateCrtKeySpec = (RSAPrivateCrtKeySpec) rsa_init_pk(prikey_type,
		        RSA_MODULU, pri_exponet, pri_p, pri_q, pri_dp, pri_dq,
		        pri_qinv, null, pub_exponet);
		try {
			privateKey = keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		//
		Signature signature = null;
		try {
			signature = Signature.getInstance(alg);
			signature.initSign(privateKey);
			signature.update(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		byte[] resp = null;
		try {
			resp = signature.sign();

			// byteArrayToString.
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return RSAUtil.byteArrayToString(resp);
	}
	
	public static boolean rsa_pubkey_verify(byte[] data, byte[] bsignature) {
		LoadConfigUtil rsaConfig = LoadConfigUtil.getInstance();
		String alg = "SHA1WITHRSA";
		String pub_exponent = "010001";
		String pub_modulus = rsaConfig.getConfigItem("RSA_MODULU");
		return rsa_pubkey_verify(data, bsignature, alg , pub_modulus, pub_exponent);
	}

	/**
	 * rsa public key validate sign
	 * 
	 * @param data
	 * @param bsignature
	 * @param alg
	 *            "SHA1WithRSA"
	 * @param pub_modulus
	 * @param pub_exponent
	 * @return
	 */
	public static boolean rsa_pubkey_verify(byte[] data, byte[] bsignature,
	        String alg, String pub_modulus, String pub_exponent) {
		PublicKey publicKey = null;
		RSAPublicKeySpec rsaPublicKeySpec = (RSAPublicKeySpec) rsa_init_pk(
		        CipherContants.RSA_KeyType_PubKey, null, null, null, null,
		        null, null, null, pub_modulus, pub_exponent);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		try {
			publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		Signature signature = null;
		boolean b = false;
		try {
			signature = Signature.getInstance(alg);
			signature.initVerify(publicKey);
			signature.update(data);
			b = signature.verify(bsignature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}

		return b;
	}

	/**
	 * 数据转换 eg 0.01 -> 000000000001
	 * 
	 * @param transAmount
	 * @return
	 */
	public static String amount2Format(String transAmount) {
		int i = 0;

		while (i < transAmount.length()) {
			if (transAmount.charAt(i) == '.') {
				if ((transAmount.length() - i - 1) == 2) {
					break;
				} else if ((transAmount.length() - i - 1) == 1) {
					transAmount += '0';
					break;
				} else if ((transAmount.length() - i - 1) == 0) {
					transAmount += "00";
					break;
				}
			}
			i++;
		}
		if (i == transAmount.length()) {
			// amount = transAmount + '.' + "00";
			// no decimal point
			transAmount += "00";
			while (transAmount.length() < 12) {
				transAmount = '0' + transAmount;
			}
		} else {
			// amount = transAmount;
			// get rid of decimal point
			transAmount = transAmount.substring(0, i)
			        + transAmount.substring(i + 1, transAmount.length());
			while (transAmount.length() < 12) {
				transAmount = '0' + transAmount;
			}
		}

		return transAmount;
	}

	public static String[] getDataByLen(String queryData) {

		return null;
	}

}
