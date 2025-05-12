/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/** Provides functionality for PIV key objects */
abstract class PIVKeyObject extends PIVObject {

  //
  // Key Roles
  //
  // The following key roles are defined as control bitmap flags, meaning multiple can be
  // set at once.
  //

  // Undefined role
  static final byte ROLE_NONE = (byte) 0x00;

  // This key can be used for card/host authentication
  // SYM: Supported for all types
  // RSA: Not supported (RSA authentication is just signing)
  // ECC: Not supported (ECC authentication is just signing)
  static final byte ROLE_AUTHENTICATE = (byte) 0x01;

  // This key can be used for key establishment schemes
  // SYM: Not supported
  // RSA: RSA Key Management (decryption)
  // ECC: ECDH
  static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;

  // This key can be used for digital signature generation
  // SYM: Not supported (Could be a MAC mechanism in the future?)
  // RSA: RSA Digital Signature
  // ECC: ECDSA
  static final byte ROLE_SIGN = (byte) 0x04;

  // RESERVED - This key can be used for digital signature verification
  static final byte ROLE_VERIFY = (byte) 0x08;

  // RESERVED - This key can be used for encryption operations
  static final byte ROLE_ENCRYPT = (byte) 0x10;

  // RESERVED - This key can be used for decryption operations
  static final byte ROLE_DECRYPT = (byte) 0x20;

  //
  // Key Attributes
  //

  // Undefined attribute
  static final byte ATTR_NONE = (byte) 0x00;

  // This symmetric key permits INTERNAL authentication (encrypting a challenge).
  // NOTE: Don't ever use this as it is totally insecure! See SECURITY.MD
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  static final byte ATTR_PERMIT_INTERNAL = (byte) 0x02;

  // This symmetric key permits EXTERNAL authentication (one-way challenge).
  // NOTE: Using this method does not provide any authentication of the card,
  //       so it is recommended to use MUTUAL authentication only.
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  static final byte ATTR_PERMIT_EXTERNAL = (byte) 0x04;

  // This symmetric key permits MUTUAL authentication (two-way challenge).
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  static final byte ATTR_PERMIT_MUTUAL = (byte) 0x08;

  // This key value may be injected under an administrative session
  // SYM: Supported / Mandatory
  // RSA: Supported
  // ECC: Supported
  static final byte ATTR_IMPORTABLE = (byte) 0x10;

  //
  // Common Key Elements
  //

  // Used by all key types to delete all key
  protected static final byte ELEMENT_CLEAR = (byte) 0xFF;

  //
  // Header Format
  //
  protected static final short HEADER_MECHANISM = (short) 4;
  protected static final short HEADER_ROLE = (short) 5;
  protected static final short HEADER_ATTRIBUTES = (short) 6;

  protected static final short LENGTH_EXTENDED_HEADERS = (short) 3;

  protected PIVKeyObject(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes) {

    super(id, modeContact, modeContactless, adminKey, LENGTH_EXTENDED_HEADERS);

    header[HEADER_MECHANISM] = mechanism;
    header[HEADER_ROLE] = role;
    header[HEADER_ATTRIBUTES] = attributes;
  }

  static PIVKeyObject create(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes)
      throws ISOException {

    PIVKeyObject key;

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        // TODO: Move all role / attr checks to inside the constructors and change from a new()
        // call to a factory (i.e. PIVKeyObjectSYM.create())

        // Role Check - The SIGN role is invalid
        if ((role & ROLE_SIGN) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Role Check - The KEY_ESTABLISH role is invalid
        if ((role & ROLE_KEY_ESTABLISH) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if ((attributes & ATTR_IMPORTABLE) == (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        key =
            new PIVKeyObjectSYM(
                id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
        break;

      case PIV.ID_ALG_RSA_1024:
      case PIV.ID_ALG_RSA_2048:
        // Attribute Check - The INTERNAL attribute MUST NOT be set for asymmetric keys
        if ((attributes & ATTR_PERMIT_INTERNAL) != (byte) 0) {
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
        key =
            new PIVKeyObjectRSA(
                id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
        break;

      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        if ((attributes & ATTR_PERMIT_INTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if ((attributes & ATTR_PERMIT_EXTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Attribute Check - The MUTUAL attribute MUST NOT be set for asymmetric keys
        if ((attributes & ATTR_PERMIT_MUTUAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        key =
            new PIVKeyObjectECC(
                id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        key = null;
    }
    return key;
  }

  boolean match(byte id, byte mechanism) {
    return (header[HEADER_ID] == id && header[HEADER_MECHANISM] == mechanism);
  }

  final byte getMechanism() {
    return header[HEADER_MECHANISM];
  }

  final byte getRoles() {
    return header[HEADER_ROLE];
  }

  final byte getAttributes() {
    return header[HEADER_ATTRIBUTES];
  }

  final boolean hasRole(byte role) {
    return ((header[HEADER_ROLE] & role) == role);
  }

  final boolean hasAttribute(byte attribute) {
    return ((header[HEADER_ATTRIBUTES] & attribute) == attribute);
  }

  /**
   * @return the length of the key in bytes
   */
  final short getKeyLengthBytes() {
    return (short) (getKeyLengthBits() / 8);
  }

  /**
   * @return the length of the key in bits
   */
  abstract short getKeyLengthBits();

  abstract short getBlockLength();

  abstract void updateElement(byte element, byte[] buffer, short offset, short length);
}
