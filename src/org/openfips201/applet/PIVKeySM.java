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
import javacard.framework.Util;
import javacard.security.MessageDigest;

/** Provides functionality for ECC PIV key objects */
final class PIVKeySM extends PIVKeyECC {

  // PERSISTENT - The secure messaging byte array for the CVC and the CVC hash
  private byte[] cvc;

  // The Secure Messaging Card Variable Certificate element
  private static final byte ELEMENT_SM_CVC = (byte) 0x88;

  static final short LENGTH_CVC_HASH = (short) 8;

  PIVKeySM(int id, byte modeContact, byte modeContactless, byte adminKey, byte mechanism, byte role, byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
  }

  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust
   *       NV RAM.
   *   <li>The ELEMENT_ECC_POINT element must be formatted as an octet string as per ANSI X9.62.
   *   <li>The ELEMENT_ECC_SECRET must be formatted as a big-endian, right-aligned big number.
   *   <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer containing the updated element
   * @param offset first byte of the element in the buffer
   * @param length the length of the element
   */
  @Override
  void update(byte element, byte[] buffer, short offset, short length) throws ISOException {

    // PRE-CONDITION - If the key is initialised, it must be explicitly cleared first
    if (isInitialised() && element != ELEMENT_CLEAR) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    if (element == ELEMENT_SM_CVC) {
      // PRE-CONDITION - The CVC cannot be zero-length
      if (length == Constants.ZERO_SHORT) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return; // Keep static analyser happy
      }

      // Generate the CVC object to hold the CVC and the CVC hash value
      if (cvc != null) {
        cvc = null;
        Platform.requestObjectDeletion();
      }

      cvc = new byte[(short) (LENGTH_CVC_HASH + length)];

      // Generate the CVC Hash as it writes more than we need
      MessageDigest digest = Platform.Cryptography.getMessageDigest(MessageDigest.ALG_SHA_256);
      digest.reset();
      digest.doFinal(buffer, offset, length, cvc, Constants.ZERO_SHORT);

      // Now copy the CVC across, starting just after the CVC hash (this will clobber the remainder 
      // of the generated hash)
      Util.arrayCopyNonAtomic(buffer, offset, cvc, LENGTH_CVC_HASH, length);
    } else {
      super.update(element, buffer, offset, length);
    }
  }

  /**
   * @return true if the key is initialised with valid key values.
   */
  @Override
  boolean isInitialised() {
    return (cvc != null && cvc.length != Constants.ZERO_SHORT && super.isInitialised());
  }

  @Override
  void clear() {
    super.clear();
    if (cvc != null) {
      // FIPS140
      if (Config.FIPS_APPROVED_MODE) {
        Platform.zeroise(cvc, Constants.ZERO_SHORT, (short) cvc.length);
      }

      cvc = null;
      Platform.requestObjectDeletion();
    }
  }

  short getCvcHash(byte[] buffer, short offset) {
    if (cvc == null) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
    }
    return Util.arrayCopyNonAtomic(cvc, Constants.ZERO_SHORT, buffer, offset, LENGTH_CVC_HASH);
  }

  short getCvc(byte[] buffer, short offset) {
    if (cvc == null) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      return 0; // Keep static analyser happy
    }
    short cvcLength = (short) (cvc.length - LENGTH_CVC_HASH);
    Util.arrayCopyNonAtomic(cvc, LENGTH_CVC_HASH, buffer, offset, cvcLength);
    return cvcLength;
  }

  short getCvcLength() {
    if (cvc == null) {
      ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      return 0; // Keep static analyser happy
    }

    return (short) (cvc.length - LENGTH_CVC_HASH);
  }
}