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

abstract class PIVKeyPKI extends PIVKey {

  static final short CONST_TAG_RESPONSE = (short) 0x7F49;
  
  PIVKeyPKI(
      int id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes) {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);


    // Role Check - The SIGN and KEY_ESTABLISH may not co-exist
    if ((role & ROLE_SIGN) == ROLE_SIGN && 
        (role & ROLE_KEY_ESTABLISH) == ROLE_KEY_ESTABLISH ) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    
    // Attribute Check - The EXTERNAL attribute MUST NOT be set for asymmetric keys
    if ((attributes & ATTR_PERMIT_EXTERNAL) != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // Attribute Check - The MUTUAL attribute MUST NOT be set for asymmetric keys
    if ((attributes & ATTR_PERMIT_MUTUAL) != (byte) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Performs the digital signature operation supported by this key type
   *
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  abstract short sign(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

  /**
   * Performs a key establishment operation supported by this key type
   *
   * @param inBuffer the input to the key establishment operation
   * @param inOffset the the location of first byte of the key establishment input
   * @param inLength the length of the key establishment input
   * @param outBuffer the key establishment output
   * @param outOffset the location of the first byte of the key establishment output
   * @return the length of the key establishment output
   */
  abstract short keyEstablish(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

  /**
   * Generates a new asymmetric key pair and returns the public component.
   *
   * @param outBuffer the output buffer to hold the generated public component
   * @param outOffset the starting position of the output buffer
   * @return The length of the generated key
   */
  abstract short generate(byte[] outBuffer, short outOffset);

  @Override
  abstract short getBlockLength();
}
