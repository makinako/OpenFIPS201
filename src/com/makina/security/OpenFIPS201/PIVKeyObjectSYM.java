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
 * Provides functionality for symmetric PIV key objects
 */
public final class PIVKeyObjectSYM extends PIVKeyObject {

    private SecretKey key;

    // The only element that can be updated in a symmetric key
    public static final byte ELEMENT_KEY		= (byte)0x80;

    // Clear any key material from this object
    public static final byte ELEMENT_KEY_CLEAR	= (byte)0xFF;

    public PIVKeyObjectSYM(byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
        super(id, modeContact, modeContactless, mechanism, role);
    }


    public void updateElement(byte element, byte[] buffer, short offset, short length) {

        if (length != getKeyLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        switch (element) {

        case ELEMENT_KEY:
            if (key == null) allocate();

            switch (key.getType()) {

            case KeyBuilder.TYPE_DES:
                try {
                    ((DESKey)key).setKey(buffer, offset);
                } catch (Exception ex)  {
                    clear();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                break;

            case KeyBuilder.TYPE_AES:
                try {
                    ((AESKey)key).setKey(buffer, offset);
                } catch (Exception ex)  {
                    clear();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                break;

            default:
                // Error state
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                break;
            }
            break;

        // Clear Key
        case ELEMENT_KEY_CLEAR:
            clear();
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }
    }

    private void allocate() {

        switch (header[HEADER_MECHANISM]) {

        case PIV.ID_ALG_DEFAULT:
        case PIV.ID_ALG_TDEA_3KEY:
            key = (SecretKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
            break;

        case PIV.ID_ALG_AES_128:
            key = (SecretKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            break;

        case PIV.ID_ALG_AES_192:
            key = (SecretKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_192, false);
            break;

        case PIV.ID_ALG_AES_256:
            key = (SecretKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            break;
        }
    }

    public void clear() {
        if (key != null) {
            key.clearKey();
        }
    }

    public boolean isInitialised() {
        return (key != null && key.isInitialized());
    }


    public short encrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        cipher.init(key, Cipher.MODE_ENCRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    public short decrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        cipher.init(key, Cipher.MODE_DECRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

}
