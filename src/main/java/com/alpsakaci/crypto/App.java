package com.alpsakaci.crypto;

import java.security.KeyPair;

import at.favre.lib.crypto.bcrypt.BCrypt.HashData;

public class App 
{
    public static void main( String[] args )
    {
        // HASHING
        String salt = Hashing.generateSalt();
        System.out.println(salt);

        HashData hash = Hashing.hashPassword(salt, "secret!");
        System.out.println(hash.rawHash);

        boolean t =  Hashing.verifyHash("secret!", salt, hash.rawHash);
        System.out.println(t);

        // AES
        String enc = AES.encrypt("test", "p@ssword".getBytes());
        System.out.println(enc);

        String dec = AES.decrypt(enc, "p@ssword".getBytes());
        System.out.println(dec);

        // RSA
        KeyPair keyPair = RSA.generateKey();
        String enc1 = RSA.encrypt("plain", keyPair.getPublic());
        System.out.println(enc1);
        String dec1 = RSA.decrypt(enc1, keyPair.getPrivate());
        System.out.println(dec1);


    }
}
