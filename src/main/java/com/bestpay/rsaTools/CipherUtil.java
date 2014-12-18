package com.bestpay.rsaTools;


import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class CipherUtil {
	
	
	
	public static final byte[] IV={(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		(byte)0x00,(byte)0x00};
	public static final byte[] Padding={(byte)0x80,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		(byte)0x00,(byte)0x00};
	
	public static final byte[] byte_pub_exponent={0x01,0x00,0x01};
	public static final String RSA_Name_Modulus="RSA_Modulus";
	
	public static final String RSA_Name_Public_Exponent="Pub_Exponent";
	public static final String RSA_Name_Private_Exponent="Pri_Exponent";
	public static final String RSA_Name_Private_P="Pri_P";
	public static final String RSA_Name_Private_Q="Pri_Q";
	public static final String RSA_Name_Private_DP="Pri_DP";
	public static final String RSA_Name_Private_DQ="Pri_DQ";
	public static final String RSA_Name_Private_QINV="Pri_QINV";
	/********************************************************************************
	 ***************************RSA**************************************************
	 *******************************************************************************/
	 
	//512bits or more
	public static KeyPair rsa_keyPair_generated(int bits){
		
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		if(keyGen == null){
			return null;
		}
		keyGen.initialize(bits); 
		KeyPair keyPair= keyGen.generateKeyPair();  
		return keyPair;
	}	
	
	//=========================rsa===================================	
	public static void  generateRsaStd(KeyPair keyPair){
		    
		RSAPrivateKey privateKey= (RSAPrivateKey) keyPair.getPrivate();
	    RSAPublicKey publicKey= (RSAPublicKey) keyPair.getPublic();
		//public key
		BigInteger public_key_exponent= publicKey.getPublicExponent();
		BigInteger public_key_modules=publicKey.getModulus();
		//output
		System.out.println(public_key_modules.toString(16));
		System.out.println(public_key_exponent.toString(16));
		//private key 
		BigInteger private_key_modules=privateKey.getModulus();
		BigInteger private_key_exponent=privateKey.getPrivateExponent();
		//output
		System.out.println(private_key_modules.toString(16));
		System.out.println(private_key_exponent.toString(16));	
	}
	
	
	//==================rsa==crt=============================================
	public synchronized static void generateRsaCrt(KeyPair keyPair,Map<String, String> map)
	{
		RSAPrivateCrtKey privateCrtKey=(RSAPrivateCrtKey) keyPair.getPrivate();
//		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic();
		
		BigInteger rsa_modulus=privateCrtKey.getModulus();
		
		//私钥
		
		BigInteger private_key_exponent=privateCrtKey.getPrivateExponent();
		
		BigInteger private_key_p=privateCrtKey.getPrimeP();
		BigInteger private_key_q=privateCrtKey.getPrimeQ();
		BigInteger private_key_dp=privateCrtKey.getPrimeExponentP();
		BigInteger private_key_dq=privateCrtKey.getPrimeExponentQ();
		BigInteger private_key_qinv=privateCrtKey.getCrtCoefficient();
		
		map.put(RSA_Name_Modulus, rsa_modulus.toString(16));
//		map.put(RSA_Name_Public_Exponent,new BigInteger(rsa_public_exponent).toString(16));
		map.put(RSA_Name_Private_P, private_key_p.toString(16));
		map.put(RSA_Name_Private_Q, private_key_q.toString(16));
		map.put(RSA_Name_Private_DP, private_key_dp.toString(16));
		map.put(RSA_Name_Private_DQ,private_key_dq.toString(16));
		map.put(RSA_Name_Private_QINV,private_key_qinv.toString(16));
		map.put(RSA_Name_Private_Exponent, private_key_exponent.toString(16));
		
	}
	
		
		
		
		
		public  static byte[] paddingData(byte[] data)
		{
			byte[] tmp=null;
			if(data.length%8==0)
			{
				tmp=new byte[data.length+8];
				System.arraycopy(data, 0, tmp, 0, data.length);
				System.arraycopy(Padding, 0, tmp, data.length, 8);
			}
			else 
			{
				tmp=new byte[data.length+8-data.length%8];
				System.arraycopy(data, 0, tmp, 0, data.length);
				System.arraycopy(Padding, 0, tmp, data.length, 8-data.length%8);
			}
			return tmp;
		}
		
		
		
		
		private static String hexString = "0123456789ABCDEF";
		public static byte[] decode(String bytes){
			ByteArrayOutputStream baos ;
	        bytes=bytes.toUpperCase();
	        if(bytes.length()%2!=0){
	        	baos= new ByteArrayOutputStream((bytes.length() +1)/ 2);  
	        } else {
	            baos= new ByteArrayOutputStream(bytes.length()/ 2);
            }
	        for (int i = 0; i < bytes.length(); i += 2){
	        	//
	        	if(i==bytes.length()-1){
	        		baos.write(hexString.indexOf(bytes.toUpperCase().charAt(i)));
	        	}
	        	if(i!=bytes.length()-1) {
	                baos.write((hexString.indexOf(bytes.charAt(i)) << 4 | hexString.indexOf(bytes  
	                   .charAt(i + 1))));
                } 
	        }
	       return baos.toByteArray();  
		}
		public static String dumpBytes(byte[] bytes) {  
	        int i;  
	        StringBuffer sb = new StringBuffer();  
	        for (i = 0; i < bytes.length; i++) {  
	            int n = bytes[i] >= 0 ? bytes[i] : 256 + bytes[i];  
	            String s = Integer.toHexString(n);  
	            if (s.length() < 2) {  
	                s = "0" + s;  
	            }  
	            if (s.length() > 2) {  
	                s = s.substring(s.length() - 2);  
	            }  
	            sb.append(s);  
	        }  
	        return sb.toString().toUpperCase();  
	    }
}
