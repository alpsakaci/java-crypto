package com.alpsakaci.crypto;

import java.security.KeyPair;
import java.util.Base64;

import at.favre.lib.crypto.bcrypt.BCrypt.HashData;

public class App {

	public static void main(String[] args) {
		System.out.println("----- HASHING -----");
		String salt = Hashing.generateSalt();
		System.out.println(salt);

		HashData hash = Hashing.hashPassword(salt, "secret!");
		System.out.println(hash.rawHash);

		boolean t = Hashing.verifyHash("secret!", salt, hash.rawHash);
		System.out.println(t);

		System.out.println("----- AES -----");
		String enc = AES.encrypt("test", "p@ssword".getBytes());
		System.out.println(enc);

		String dec = AES.decrypt(enc, "p@ssword".getBytes());
		System.out.println(dec);

		System.out.println("----- RSA -----");
		KeyPair keyPair = RSA.generateKey();
		String enc1 = RSA.encrypt("plain", keyPair.getPublic());
		System.out.println(enc1);
		String dec1 = RSA.decrypt(enc1, keyPair.getPrivate());
		System.out.println(dec1);

		System.out.println("----- KEY DERIVATION -----");
		String salt2 = Hashing.generateSalt();
		byte[] generatedKey = KeyDerivation.generateKey("your_password", salt2, 100000, 512);
		Base64.Encoder encoder = Base64.getEncoder();
		System.out.println(encoder.encodeToString(generatedKey));
	}

}
