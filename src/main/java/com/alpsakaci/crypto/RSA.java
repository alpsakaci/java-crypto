package com.alpsakaci.crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RSA {

	public static KeyPair generateKey() {
		KeyPair keyPair = null;
		try {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			keyPair = keygen.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return keyPair;
	}

	public static String exportPrivateKey(KeyPair keyPair) {
		return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
	}

	public static String exportPublicKey(KeyPair keyPair) {
		return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
	}

	public static PublicKey readPublicKey(String key) {
		PublicKey publicKey = null;
		try {
			byte[] privateKeyBytes = Base64.getDecoder().decode(key);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec rks = new X509EncodedKeySpec(privateKeyBytes);
			publicKey = kf.generatePublic(rks);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return publicKey;
	}

	public static PrivateKey readPrivateKey(String key) {
		PrivateKey privateKey = null;
		try {
			byte[] privateKeyBytes = Base64.getDecoder().decode(key);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
			privateKey = kf.generatePrivate(ks);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return privateKey;
	}

	public static String encrypt(String plaintext, PublicKey publicKey) {
		Base64.Encoder encoder = Base64.getEncoder();
		byte[] cipherText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey,
					new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
			cipherText = cipher.doFinal(plaintext.getBytes());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encoder.encodeToString(cipherText);
	}

	public static String decrypt(String cipherText, PrivateKey privateKey) {
		Base64.Decoder decoder = Base64.getDecoder();
		byte[] cipherEncoded = decoder.decode(cipherText.getBytes());
		byte[] plainText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privateKey,
					new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
			plainText = cipher.doFinal(cipherEncoded);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return new String(plainText);
	}

}
