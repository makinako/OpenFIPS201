/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201 Copyright: (c) 2025 Commonwealth of Australia 
 * Author: Kim O'Sullivan / Makina (kim@makina.com.au / @makinako)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

package org.openfips201.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.SecretKey;
import javacard.security.CryptoException;

/** Provides functionality for symmetric PIV key objects */
final class PIVKeySYM extends PIVKey {

  // The only element that can be updated in a symmetric key
  private static final byte ELEMENT_KEY = (byte) 0x80;

  // PERSISTENT - Secret key value
  private SecretKey key;

  PIVKeySYM(int id, byte modeContact, byte modeContactless, byte adminKey, byte mechanism, byte role, byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    // Role Check - The KEY_ESTABLISH role is invalid
    if ((role & ROLE_KEY_ESTABLISH) == ROLE_KEY_ESTABLISH) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Role Check - The KEY_SIGN and KEY_AUTHENTICATE may not co-exist
    if ((role & ROLE_SIGN) == ROLE_SIGN && (role & ROLE_AUTHENTICATE) == ROLE_AUTHENTICATE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Attribute Check - The IMPORTABLE attribute must always be present
    if ((attributes & ATTR_IMPORTABLE) != ATTR_IMPORTABLE) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Attribute Check - If the SIGN role is set, neither PERMIT_MUTUAL nor
    //           PERMIT_EXTERNAL may be set
    if ((role & ROLE_SIGN) == ROLE_SIGN && ((attributes & ATTR_PERMIT_MUTUAL) == ATTR_PERMIT_MUTUAL
        || (attributes & ATTR_PERMIT_EXTERNAL) == ATTR_PERMIT_EXTERNAL)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Attribute Check - At least one of PERMIT_EXTERNAL or PERMIT_MUTUAL must be set
    if ((role & ROLE_AUTHENTICATE) == ROLE_AUTHENTICATE && (attributes & ATTR_PERMIT_MUTUAL) != ATTR_PERMIT_MUTUAL
        && (attributes & ATTR_PERMIT_EXTERNAL) != ATTR_PERMIT_EXTERNAL) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  @Override
  void update(byte element, byte[] buffer, short offset, short length) throws ISOException {

    // We only support the 'Key' element
    if (ELEMENT_KEY == element) {
      // PRE-CONDITION - If the key is initialised, it must be explicitly cleared first
      if (isInitialised()) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }

      // PRE-CONDITION - The input data must match the expected key length
      if (length != getKeyLengthBytes()) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }

      allocate();

      switch (key.getType()) {
      case KeyBuilder.TYPE_DES:
        try {
          ((DESKey) key).setKey(buffer, offset);
        } catch (Exception ex) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        break;

      case KeyBuilder.TYPE_AES:
        try {
          ((AESKey) key).setKey(buffer, offset);
        } catch (Exception ex) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        break;

      default:
        // Insane state
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
        break;
      }
    } else {
      // Fall back
      super.update(element, buffer, offset, length);
    }

  }

  private void allocate() throws ISOException {
    if (!Platform.Cryptography.supportsMechanism(getMechanism())) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    clear();
    byte keyType;
    short keyLen;
    switch (header[HEADER_MECHANISM]) {
    case Constants.ID_ALG_DEFAULT:
    case Constants.ID_ALG_TDEA_3KEY:
      keyType = KeyBuilder.TYPE_DES;
      keyLen = KeyBuilder.LENGTH_DES3_3KEY;
      break;

    case Constants.ID_ALG_AES_128:
      keyType = KeyBuilder.TYPE_AES;
      keyLen = KeyBuilder.LENGTH_AES_128;
      break;

    case Constants.ID_ALG_AES_192:
      keyType = KeyBuilder.TYPE_AES;
      keyLen = KeyBuilder.LENGTH_AES_192;
      break;

    case Constants.ID_ALG_AES_256:
      keyType = KeyBuilder.TYPE_AES;
      keyLen = KeyBuilder.LENGTH_AES_256;
      break;

    default:
      ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
      return; // Keep compiler happy
    }

    try {
      key = (SecretKey) Platform.Cryptography.buildKey(keyType, keyLen);
    } catch (CryptoException ex) {
      Platform.Cryptography.onCryptoException(getMechanism(), ex);
    }
  }

  @Override
  void clear() {
    if (key != null) {
      key.clearKey();
      key = null;
      Platform.requestObjectDeletion();
    }
  }

  @Override
  boolean isInitialised() {
    return (key != null && key.isInitialized());
  }

  @Override
  short getBlockLength() throws ISOException {
    switch (getMechanism()) {
    case Constants.ID_ALG_DEFAULT:
    case Constants.ID_ALG_TDEA_3KEY:
      return (short) 8;

    case Constants.ID_ALG_AES_128:
    case Constants.ID_ALG_AES_192:
    case Constants.ID_ALG_AES_256:
      return (short) 16;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }
  }

  @Override
  short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
    case Constants.ID_ALG_DEFAULT:
    case Constants.ID_ALG_TDEA_3KEY:
      return KeyBuilder.LENGTH_DES3_3KEY;

    case Constants.ID_ALG_AES_128:
      return KeyBuilder.LENGTH_AES_128;

    case Constants.ID_ALG_AES_192:
      return KeyBuilder.LENGTH_AES_192;

    case Constants.ID_ALG_AES_256:
      return KeyBuilder.LENGTH_AES_256;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }
  }

  short encipher(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    // PRE-CONDITION 1 - The length must be equal to the block length
    if (inLength != getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    try {
      return Platform.Cryptography.encipher(key, inBuffer, inOffset, inLength, outBuffer, outOffset);
    } catch (CryptoException ex) {
      Platform.Cryptography.onCryptoException(getMechanism(), ex);
      return (short) 0; // Keep compiler happy
    }
  }
}
