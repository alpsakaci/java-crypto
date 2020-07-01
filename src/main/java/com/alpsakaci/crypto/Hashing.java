package com.alpsakaci.crypto;

import java.security.SecureRandom;
import java.util.Base64;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.HashData;

public class Hashing {

    public static String generateSalt() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] salt = Bytes.random(16, secureRandom).array();
		String saltstr = Base64.getEncoder().encodeToString(salt);
		
		return saltstr;
	}
	
	public static HashData hashPassword(String salt, String password) {
		byte[] saltBytes = Base64.getDecoder().decode(salt);
		HashData hash = BCrypt.withDefaults().hashRaw(12, saltBytes, password.getBytes());
		
		return hash;
	}
	
	public static boolean verifyHash(String password, String salt, byte[] hash) {
		byte[] saltBytes = Base64.getDecoder().decode(salt);
		BCrypt.Result result = BCrypt.verifyer().verify(password.getBytes(), 12, saltBytes, hash);
		
		return result.verified;
    }
    
}
