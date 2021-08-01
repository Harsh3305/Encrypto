package com.example.encrypto;

import com.example.encrypto.AES.AES;
import com.example.encrypto.RSA.RSA;

public class Encryption {
    private String encryptionAlgorithm;
    private AES aesEncryption;
    private RSA rsaEncryption;
    public Encryption (String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        if (encryptionAlgorithm.equals("AES")) {
            aesEncryption = new AES();
        }
        else if (encryptionAlgorithm.equals("RSA")) {
            rsaEncryption = new RSA();
        }
    }

    public String encrypt (String plainText) throws Exception {
        if (encryptionAlgorithm.equals("RSA")) {
            return rsaEncryption.encrypt(plainText);
        }
        else if (encryptionAlgorithm.equals("AES")) {
            return aesEncryption.encrypt(plainText);
        }
        else {
            return "";
        }
    }

    public String decrypt (String cipherText) throws Exception {
        if (encryptionAlgorithm.equals("RSA")) {
            return rsaEncryption.decrypt(cipherText);
        }
        else if (encryptionAlgorithm.equals("AES")) {
            return aesEncryption.decrypt(cipherText);
        }
        else {
            return "";
        }
    }

}