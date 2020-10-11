package alpsakaci;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.Base64;
import java.util.logging.Logger;

import org.junit.Test;

import com.alpsakaci.crypto.AES;
import com.alpsakaci.crypto.Hashing;
import com.alpsakaci.crypto.KeyDerivation;
import com.alpsakaci.crypto.RSA;

import at.favre.lib.crypto.bcrypt.BCrypt.HashData;

public class AppTest {

	private static final Logger LOG = Logger.getGlobal();
    
    @Test
    public void generateSaltTest() {
    	String salt = Hashing.generateSalt();
    	assertNotNull(salt);
    	LOG.info("Salt Generated: " + salt);
    }
    
    @Test
    public void bcryptPasswordHashingTest() {
    	String salt = Hashing.generateSalt();
    	HashData hash = Hashing.hashPassword(salt, "secret");
    	assertNotNull(hash);
    	LOG.info(hash.toString());
    }
    
    @Test
    public void bcryptVerifyHashTest() {
    	String password = "secret";
    	String salt = Hashing.generateSalt();
    	HashData hash = Hashing.hashPassword(salt, password);
    	boolean isValid = Hashing.verifyHash(password, salt, hash.rawHash);
    	assertTrue(isValid);
    	LOG.info("Hash is valid.");
    }
    
    @Test
    public void aesEncryptTest() {
    	String password = "secret";
    	String encryptedText = AES.encrypt("plaintext", password.getBytes());
    	assertNotNull(encryptedText);
    	LOG.info("Text encrypted: " + encryptedText);
    }
    
    @Test
    public void aesDecryptTest() {
    	String password = "secret";
    	String encryptedText = AES.encrypt("plaintext", password.getBytes());
    	
    	String decryptedText = AES.decrypt(encryptedText, password.getBytes());
    	assertNotNull(decryptedText);
    	LOG.info("Text decrypted: " + decryptedText);
    }
    
    @Test
    public void rsaEncryptTest() {
    	KeyPair keyPair = RSA.generateKey();
		String encryptedText = RSA.encrypt("plaintext", keyPair.getPublic());
		assertNotNull(encryptedText);
		LOG.info("Text encrypted: " + encryptedText);
    }
    
    @Test
    public void rsaDecryptTest() {
    	KeyPair keyPair = RSA.generateKey();
		String encryptedText = RSA.encrypt("plaintext", keyPair.getPublic());
		
		String decryptedText = RSA.decrypt(encryptedText, keyPair.getPrivate());
		assertNotNull(decryptedText);
		LOG.info("Text decrypted: " + decryptedText);
    }
    
    @Test
    public void pbkdf2GenerateKeyTest() {
    	String password = "secret";
    	String salt = Hashing.generateSalt();
		byte[] generatedKey = KeyDerivation.generateKey(password, salt, 100000, 512);
		assertNotNull(generatedKey);
		Base64.Encoder encoder = Base64.getEncoder();
		LOG.info("Key generated: " + encoder.encodeToString(generatedKey));
    }
    
}
