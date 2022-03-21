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
import javacard.framework.JCSystem;

/** Provides functionality for PIV key objects */
public abstract class PIVKeyObject extends PIVObject {

  //
  // Key Roles
  //
  // The following key roles are defined as control bitmap flags, meaning multiple can be
  // set at once.
  //

  // Undefined role
  public static final byte ROLE_NONE = (byte) 0x00;

  // This key can be used for card/host authentication
  // SYM: Supported for all types
  // RSA: Not supported (RSA authentication is just signing)
  // ECC: Not supported (ECC authentication is just signing)
  public static final byte ROLE_AUTHENTICATE = (byte) 0x01;

  // This key can be used for key establishment schemes
  // SYM: Not supported
  // RSA: RSA Key Management (decryption)
  // ECC: ECDH
  public static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;

  // This key can be used for digital signature generation
  // SYM: Not supported (Could be a MAC mechanism in the future?)
  // RSA: RSA Digital Signature
  // ECC: ECDSA
  public static final byte ROLE_SIGN = (byte) 0x04;

  // Used for digital signature verification
  // NOTE: Currently there is no PIV case for this, but reserve it in case we want the extension
  // SYM: Not supported (Could be a MAC mechanism in the future?)
  // RSA: Not supported
  // ECC: Not supported
  public static final byte ROLE_VERIFY = (byte) 0x08;

  // This key can be used for secure messaging establishment
  // SYM: Not supported
  // RSA: Not supported
  // ECC: Opacity ZKM (Must have CVC component)
  public static final byte ROLE_SECURE_MESSAGING = (byte) 0x10;

  // RESERVED - This key can be used for encryption operations
  public static final byte ROLE_ENCRYPT = (byte) 0x20;

  // RESERVED - This key can be used for decryption operations
  public static final byte ROLE_DECRYPT = (byte) 0x40;

  //
  // Key Attributes
  //

  // Undefined attribute
  public static final byte ATTR_NONE = (byte) 0x00;

  // This key can be used for administrative authentication
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  public static final byte ATTR_ADMIN = (byte) 0x01;

  // This symmetric key permits INTERNAL authentication (encrypting a challenge).
  // NOTE: Don't ever use this as it is totally insecure! See SECURITY.MD
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  public static final byte ATTR_PERMIT_INTERNAL = (byte) 0x02;

  // This symmetric key permits EXTERNAL authentication (one-way challenge).
  // NOTE: Using this method does not provide any authentication of the card,
  //       so it is recommended to use MUTUAL authentication only.
  // SYM: Supported
  // RSA: Not supported
  // ECC: Not supported
  public static final byte ATTR_PERMIT_EXTERNAL = (byte) 0x04;

  // This key value may be injected under an administrative session
  // SYM: Supported (Must always be set!)
  // RSA: Supported
  // ECC: Supported
  public static final byte ATTR_IMPORTABLE = (byte) 0x10;

  //
  // Common Key Elements
  //

  // Used by all key types to delete all key
  protected static final byte ELEMENT_CLEAR = (byte) 0xFF;

  //
  // Header Format
  //

  protected static final short HEADER_MECHANISM = (short) 3;
  protected static final short HEADER_ROLE = (short) 4;
  protected static final short HEADER_ATTRIBUTES = (short) 5;

  private static final short FLAGS_AUTHENTICATED = (short) 0;
  private static final short LENGTH_FLAGS = (short) 1;

  // Transient declaration
  private final boolean[] securityFlags;

  protected PIVKeyObject(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {

    super(id, modeContact, modeContactless);

    header[HEADER_MECHANISM] = mechanism;
    header[HEADER_ROLE] = role;
    header[HEADER_ATTRIBUTES] = attributes;

    securityFlags = JCSystem.makeTransientBooleanArray(LENGTH_FLAGS, JCSystem.CLEAR_ON_DESELECT);

    resetSecurityStatus();
  }

  public static PIVKeyObject create(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes)
      throws ISOException {

    PIVKeyObject key;

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        // Role Check - The SIGN role is invalid
        if ((role & ROLE_SIGN) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Role Check - The KEY_ESTABLISH role is invalid
        if ((role & ROLE_KEY_ESTABLISH) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Role Check - The SECURE_MESSAGING role is invalid
        if ((role & ROLE_SECURE_MESSAGING) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Attribute Check - The IMPORTABLE attribute must be set for symmetric keys
        if ((attributes & ATTR_IMPORTABLE) == (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        key = new PIVKeyObjectSYM(id, modeContact, modeContactless, mechanism, role, attributes);
        break;

      case PIV.ID_ALG_RSA_1024:
      case PIV.ID_ALG_RSA_2048:
        // Attribute Check - The ADMIN attribute MUST NOT be set for asymmetric keys
        if ((attributes & ATTR_ADMIN) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Attribute Check - The INTERNAL attribute MUST NOT be set for asymmetric keys
        if ((attributes & ATTR_PERMIT_INTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // Attribute Check - The EXTERNAL attribute MUST NOT be set for asymmetric keys
        if ((attributes & ATTR_PERMIT_EXTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        key = new PIVKeyObjectRSA(id, modeContact, modeContactless, mechanism, role, attributes);
        break;

      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        if ((attributes & ATTR_ADMIN) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if ((attributes & ATTR_PERMIT_INTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if ((attributes & ATTR_PERMIT_EXTERNAL) != (byte) 0) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        key = new PIVKeyObjectECC(id, modeContact, modeContactless, mechanism, role, attributes);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return null; // Keep the compiler happy
    }
    return key;
  }

  public boolean match(byte id, byte mechanism) {
    return (header[HEADER_ID] == id && header[HEADER_MECHANISM] == mechanism);
  }

  public final byte getMechanism() {
    return header[HEADER_MECHANISM];
  }

  public final byte getRoles() {
    return header[HEADER_ROLE];
  }

  public final byte getAttributes() {
    return header[HEADER_ATTRIBUTES];
  }

  public final boolean hasRole(byte role) {
    return ((header[HEADER_ROLE] & role) == role);
  }

  public final boolean hasAttribute(byte attribute) {
    return ((header[HEADER_ATTRIBUTES] & attribute) == attribute);
  }

  public final void resetSecurityStatus() {
    securityFlags[FLAGS_AUTHENTICATED] = false;
  }

  public final void setSecurityStatus() {
    securityFlags[FLAGS_AUTHENTICATED] = true;
  }

  public final boolean getSecurityStatus() {
    return (securityFlags[FLAGS_AUTHENTICATED]);
  }

  /**
   * @return the length of the key in bytes
   */
  public final short getKeyLengthBytes() {
    return (short) (getKeyLengthBits() / 8);
  }

  /**
   * @return the length of the key in bits
   */
  public abstract short getKeyLengthBits();

  public abstract short getBlockLength();

  public abstract void updateElement(byte element, byte[] buffer, short offset, short length);
}
