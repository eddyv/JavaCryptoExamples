package com.eddyv.example;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MaxKeyLength
 */
public class CryptoBasicChecks {
    private CryptoBasicChecks() {
    }

    /**
     * Returns the max key length that is able to be generated on the machine.
     * 
     * @throws NoSuchAlgorithmException
     */
    public static int getAESMaxKeyLength() throws NoSuchAlgorithmException {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        return maxKeySize;
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Provider provider = Security.getProvider("BC");
        Iterator<Object> it = provider.keySet().iterator();
        while (it.hasNext()) {
            String entry = (String) it.next();
            // this indicates the entry actually refers to another entry
            if (entry.startsWith("Alg.Alias.")) {
                entry = entry.substring("Alg.Alias.".length());
            }
            String factoryClass = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(factoryClass.length() + 1);
            System.out.println(factoryClass + ": " + name);
        }
    }

}