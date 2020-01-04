package com.eddyv.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
 * SimpleTests
 * Handles the basic tests of checking if the providers, policys, etc.. are correctly installed
 */
public class SimpleTests {

    /**
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * 
     */
    @Test
    public void testPolicyInstallation() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        final byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        // create a 64 bit secret key from raw bytes
        final SecretKey key64 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
                "Blowfish");
        // create a cipher and attempt to encrypt the data block with our key
        final Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key64);
        c.doFinal(data);
        System.out.println("64 bit test: passed");

        // create a 192 bit secret key from raw bytes
        final SecretKey key192 = new SecretKeySpec(new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }, "Blowfish");

        // now try encrypting with the larger key
        c.init(Cipher.ENCRYPT_MODE, key192);
        c.doFinal(data);
        System.out.println("192 bit test: passed");
        System.out.println("Tests completed");
    }

    /**
     * Checks if bouncycastle was properly installed
     */
    @Test
    public void testBouncyCastleProviderInstallation() {
        Security.addProvider(new BouncyCastleProvider());
        String providerName = "BC";
        assertNotEquals("Check that bouncycastle provider can be found. Null if not found",
                Security.getProvider(providerName), null);
    }

    /**
     * Check if the AES key length can be as high as Integer.MAX_VALUE.
     * 
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testAESMaxKeyLength() throws NoSuchAlgorithmException {
        assertEquals("Checking is max key length is equal to Integer.Max_value", Integer.MAX_VALUE,
                CryptoBasicChecks.getAESMaxKeyLength());
    }
}