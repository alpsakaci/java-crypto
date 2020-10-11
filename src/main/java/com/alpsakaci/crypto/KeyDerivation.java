package com.alpsakaci.crypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class KeyDerivation {

	public static byte[] generateKey(String password, String salt, int iterations, int keyLength) {

		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterations, keyLength);
			SecretKey secretKey = skf.generateSecret(keySpec);

			return secretKey.getEncoded();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

	}

}
