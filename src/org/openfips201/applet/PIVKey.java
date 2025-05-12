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

/** Provides functionality for PIV key objects */
abstract class PIVKey extends PIVObject {

  //
  // Key Roles
  //
  // The following key roles are defined as control bitmap flags, meaning multiple
  // can be
  // set at once.
  //

  // This key can be used for card/host authentication
  // SYM: Supported for all types
  // RSA: Not supported (RSA authentication is just signing)
  // ECC: Not supported (ECC authentication is just signing)
  static final byte ROLE_AUTHENTICATE = (byte) 0x01;

  // This key can be used for key establishment schemes
  // SYM: Not supported
  // RSA: RSA Key Management (decryption)
  // ECC: ECDH or PIV-SM
  static final byte ROLE_KEY_ESTABLISH = (byte) 0x02;

  // This key can be used for digital signature generation
  // SYM: Internal authenticate (challenge Response)
  // RSA: RSA Digital Signature
  // ECC: ECDSA
  static final byte ROLE_SIGN = (byte) 0x04;

  //
  // Key Attributes
  //

  // This symmetric key permits EXTERNAL authentication (one-way challenge).
  // NOTE: Using this method does not provide any authentication of the card,
  // so it is recommended to use MUTUAL authentication only.
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
  
  // For RSA keys only, the Chinese Remainder Theorem (CRT) key format will be used
  static final byte ATTR_RSA_CRT = (byte) 0x20;
  
  //
  // Common Key Elements
  //

  // Used by all key types to delete all key
  protected static final byte ELEMENT_CLEAR = (byte) 0x9F;

  // The default administrative key reference
  static final byte DEFAULT_ADMIN_KEY = (byte) 0x9B;
  
  // The mask that derived keys may use to 

  //
  // Extended header Format (must start beyond the PIVObject headers)
  //
  static final short HEADER_ADMIN_KEY = (short) 2;
  static final short HEADER_MECHANISM = (short) 3;
  static final short HEADER_ROLE = (short) 4;
  static final short HEADER_ATTRIBUTES = (short) 5;

  private static final short LENGTH_EXTENDED_HEADER = (short) 6;

  protected PIVKey(int id, byte modeContact, byte modeContactless, byte adminKey, byte mechanism,
      byte role, byte attributes) {

    super(id, modeContact, modeContactless);

    // If the administrative key is not specified, use the default (9B) key.
    if (adminKey == (byte) 0) {
      adminKey = DEFAULT_ADMIN_KEY;
    }
    
    header[HEADER_ADMIN_KEY] = adminKey;
    header[HEADER_MECHANISM] = mechanism;
    header[HEADER_ROLE] = role;
    header[HEADER_ATTRIBUTES] = attributes;
  }

  @Override
  protected short getHeaderLength() {
    return LENGTH_EXTENDED_HEADER;
  }

  @Override
  protected short getHeader(TLVWriter writer) {      
    // We write without a parent tag.
    writer.write(Constants.TAG_OBJECT_ID, id);
    writer.write(Constants.TAG_MODE_CONTACT, header[HEADER_MODE_CONTACT]);
    writer.write(Constants.TAG_MODE_CONTACTLESS, header[HEADER_MODE_CONTACTLESS]);
    writer.write(Constants.TAG_ADMIN_KEY, header[HEADER_ADMIN_KEY]);
    writer.write(Constants.TAG_KEY_MECHANISM, header[HEADER_MECHANISM]);
    writer.write(Constants.TAG_KEY_ROLE, header[HEADER_ROLE]);
    writer.write(Constants.TAG_KEY_ATTRIBUTE, header[HEADER_ATTRIBUTES]);    
    return writer.finish();
  }

  @Override
  byte getAdminKey() {
    return header[HEADER_ADMIN_KEY];
  }

  /**
   * Returns the single-byte identifier for this key object
   * 
   * @return the single-byte identifier
   */
  final byte getKeyId() {
    return (byte) (this.id & 0xFF);
  }

  /*
   * Searches all PIVObject instances linked from this object until it matches one by id
   */
  final PIVKey select(int id, byte mechanism) {
    PIVObject current = this;

    while (current != null) {
      if (current.id == id) {
        PIVKey result = (PIVKey)current;
        
        // For this method, only return it if the mechanism also matches
        if (result.getMechanism() == mechanism) return result;
      }
      current = current.nextObject;
    }

    return null;
  }
  
  final byte getMechanism() {
    return header[HEADER_MECHANISM];
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

  void update(byte element, byte[] buffer, short offset, short length) {
    // Clear all key parts
    if (ELEMENT_CLEAR == element) {
      clear();
    } else {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }
  

  /*
   * Key Factory
   */
  static PIVKey createKey(int id, byte modeContact, byte modeContactless, byte adminKey, TLVReader reader) throws ISOException {

    //
    // PRE-CONDITIONS
    //
    
    // PRE-CONDITION:  Make sure the id is within the range for a key
    if (id > Constants.KEY_ID_MAX_VALUE) {
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_INVALID_LENGTH);
    }
    
    // PRE-CONDITION: Make sure the id is not a pre-existing verifier identity
    if (PIVVerifier.isVerifierId((byte)(id & 0xFF))) {
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_INVALID_VALUE);
    }

    // PRE-CONDITION: The 'KEY MECHANISM' tag MUST be present
    if (!reader.match(Constants.TAG_KEY_MECHANISM)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_MECHANISM_MISSING);
    }

    // PRE-CONDITION: The 'KEY MECHANISM' tag MUST have length 1 only
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_MECHANISM_INVALID);
    }
    byte mechanism = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION: The supplied mechanism must be supported by this instance
    // FIPS: This is the critical code-point whereby non-approved algorithms are restricted
    // when the applet is in the approved mode!
    if (!Platform.Cryptography.supportsMechanism(mechanism)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // PRE-CONDITION: The 'KEY ROLE' tag MUST be present
    if (!reader.match(Constants.TAG_KEY_ROLE)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_ROLE_MISSING);
    }

    // PRE-CONDITION: The 'KEY ROLE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH);
    }
    byte role = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION: The 'KEY ATTRIBUTE' tag MUST be present
    if (!reader.match(Constants.TAG_KEY_ATTRIBUTE)) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_ATTR_MISSING);
    }

    // PRE-CONDITION: The 'KEY ATTRIBUTE' tag MUST have length 1
    if (reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH);
    }
    byte attributes = reader.toByte();
    reader.moveNext();
    
    //
    // EXECUTION
    //
    
    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == Constants.ID_ALG_DEFAULT) {
      mechanism = Constants.ID_ALG_TDEA_3KEY;
    }

    switch (mechanism) {
    case Constants.ID_ALG_DEFAULT:
    case Constants.ID_ALG_TDEA_3KEY:
    case Constants.ID_ALG_AES_128:
    case Constants.ID_ALG_AES_192:
    case Constants.ID_ALG_AES_256:
      return new PIVKeySYM(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    case Constants.ID_ALG_RSA_1024:
    case Constants.ID_ALG_RSA_2048:
    case Constants.ID_ALG_RSA_3072:
    case Constants.ID_ALG_RSA_4096:
      return new PIVKeyRSA(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    case Constants.ID_ALG_ECC_P256:
    case Constants.ID_ALG_ECC_P384:
      return new PIVKeyECC(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    case Constants.ID_ALG_ECC_CS2:
    case Constants.ID_ALG_ECC_CS7:
      return new PIVKeySM(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    default:
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      return null; // Keep compiler happy
    }
  }  
}
