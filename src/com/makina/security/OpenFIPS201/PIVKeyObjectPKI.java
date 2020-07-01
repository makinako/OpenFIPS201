/******************************************************************************
MIT License

  Project: OpenFIPS201
Copyright: (c) 2017 Commonwealth of Australia
   Author: Kim O'Sullivan - Makina (kim@makina.com.au)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

package com.makina.security.OpenFIPS201;

import javacardx.crypto.*;
import javacard.security.*;
import javacard.framework.*;

/**
 * Provides functionality for asymmetric PIV key objects
 */
public final class PIVKeyObjectPKI extends PIVKeyObject {

    private Key privateKey;
    private RSAPublicKey publicKey;
    private KeyPair keyPair;
    private boolean isCrtKey;

    // The list of elements that can be updated for an asymmetric key

    // RSA Modulus Element
    public static final byte ELEMENT_RSA_N	= (byte)0x81;

    // RSA Public Exponent
    public static final byte ELEMENT_RSA_E	= (byte)0x82;

    // RSA Private Exponent
    public static final byte ELEMENT_RSA_D	= (byte)0x83;

    // RSA Prime Exponent P (CRT oly)
    public static final byte ELEMENT_RSA_P	= (byte)0x84;

    // RSA Prime Exponent Q (CRT only)
    public static final byte ELEMENT_RSA_Q	= (byte)0x85;

    // RSA D mod P - 1 (CRT only)
    public static final byte ELEMENT_RSA_DP	= (byte)0x86;

    // RSA D mod Q - 1 (CRT only)
    public static final byte ELEMENT_RSA_DQ	= (byte)0x87;

    // RSA Inverse Q (CRT only)
    public static final byte ELEMENT_RSA_PQ	= (byte)0x88;

    // Clear any key material from this object
    public static final byte ELEMENT_RSA_CLEAR	= (byte)0xFF;

    public PIVKeyObjectPKI(byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
        super(id, modeContact, modeContactless, mechanism, role);
    }

    public void updateElement(byte element, byte[] buffer, short offset, short length) {

        switch (element) {

        // RSA Modulus Element
        case ELEMENT_RSA_N:
            if (length != getKeyLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (publicKey == null || privateKey == null) allocate();
            if (isCrtKey) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            publicKey.setModulus(buffer, offset, length);
            ((RSAPrivateKey) privateKey).setModulus(buffer, offset, length);
            break;

        // RSA Public Exponent
        case ELEMENT_RSA_E:
            if (length == (short)0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (publicKey == null) allocate();
            publicKey.setExponent(buffer, offset, length);
            break;

        // RSA Private Exponent
        case ELEMENT_RSA_D:
            if (length != getKeyLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (privateKey == null) allocate();
            if (isCrtKey) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
            ((RSAPrivateKey) privateKey).setExponent(buffer, offset, length);
            break;

        /*
        // RSA Prime Exponent P
        case ELEMENT_RSA_P:
        	if (privateKey == null) allocate();
        	break;

        // RSA Prime Exponent Q
        case ELEMENT_RSA_Q:
        	if (privateKey == null) allocate();
        	break;

        // RSA D mod P - 1
        case ELEMENT_RSA_DP:
        	if (privateKey == null) allocate();
        	break;

        // RSA D mod Q - 1
        case ELEMENT_RSA_DQ:
        	if (privateKey == null) allocate();
        	break;

        // RSA Inverse Q
        case ELEMENT_RSA_PQ:
        	if (privateKey == null) allocate();
        	break;
        */

        // Clear Key
        case ELEMENT_RSA_CLEAR:
            if (publicKey != null) publicKey.clearKey();
            if (privateKey != null) privateKey.clearKey();
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }

    }

    /**
     * Writes the private exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the exponent to write
     */
    public void setPrivateExponent(byte[] buffer, short offset, short length) {
        if (privateKey == null) allocate();
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        if (isCrtKey) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        ((RSAPrivateKey) privateKey).setExponent(buffer, offset, length);
    }

    /**
     * Writes the public exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the exponent to write
     */
    public void setPublicExponent(byte[] buffer, short offset, short length) {
        if (publicKey == null) allocate();
        publicKey.setExponent(buffer, offset, length);
    }

    /**
     * Writes the modulus of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the modulus to write
     */
    public void setModulus(byte[] buffer, short offset, short length) {
        if (privateKey == null || publicKey == null) allocate();
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        if (isCrtKey) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        ((RSAPrivateKey) privateKey).setModulus(buffer, offset, length);
        publicKey.setModulus(buffer, offset, length);
    }

    /**
     * Writes the public exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @return The length of the public exponent
     */
    public short getPublicExponent(byte[] buffer, short offset) {
        return publicKey.getExponent(buffer, offset);
    }

    /**
     * Writes the modulus of the RSA key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @return The length of the modulus
     */
    public short getModulus(byte[] buffer, short offset) {
        return publicKey.getModulus(buffer, offset);
    }

    private void allocate() {

        isCrtKey = false;

        // Generate the appropriate key(s)
        switch (header[HEADER_MECHANISM]) {

        case PIV.ID_ALG_RSA_1024:
            try {
                keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            } catch (CryptoException e) {
	        if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
	            isCrtKey = true;
                }
	    }
            break;

        case PIV.ID_ALG_RSA_2048:
            try {
                keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
            } catch (CryptoException e) {
	        if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
                    keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
	            isCrtKey = true;
                }
	    }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            break;
        }

        privateKey = keyPair.getPrivate();
        publicKey = (RSAPublicKey)keyPair.getPublic();
    }

    public void clear() {

        if (privateKey != null) {
            privateKey.clearKey();
        }
        if (publicKey != null) {
            publicKey.clearKey();
        }

    }

    public boolean isInitialised() {
        return (privateKey != null && privateKey.isInitialized() &&
                publicKey != null && publicKey.isInitialized());
    }

    public void generate() {
        if (privateKey == null || publicKey == null) allocate();
        keyPair.genKeyPair();
    }

    public short encrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        cipher.init(privateKey, Cipher.MODE_ENCRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    public short decrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }
}
