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

/**
 * A utility class holding constant values and identifiers used throughout the NIST PIV (Personal Identity Verification) applet.
 * <p>
 * This class includes Boolean constants, numeric constants, PIV-specific object identifiers,
 * supported mechanisms, card holder verification methods, and TLV (Tag-Length-Value) construction values.
 * It also contains custom status words for PIV administrative error handling.
 * <p>
 * Note: This class is final and contains only static elements.
 */
final class Constants {

  /**
   * Private constructor to prevent instantiation of this utility class.
   */
  private Constants() {
  }

  ////////////////////////////////////////////////////////////////////////////////
  // General Constants
  ////////////////////////////////////////////////////////////////////////////////

  // Boolean

  // A {@code short} constant representing a boolean TRUE value.
  static final short TRUE_SHORT = (short) 0xA5A5;

  // A {@code short} constant representing a boolean FALSE value.
  static final short FALSE_SHORT = (short) 0x5A5A;

  // A {@code byte} constant representing a boolean TRUE value.
  static final byte TRUE_BYTE = (byte) 0xA5;

  // A {@code byte} constant representing a boolean FALSE value.
  static final byte FALSE_BYTE = (byte) 0x5A;

  // Zero Constants

  // A {@code short} constant representing numeric zero.
  static final short ZERO_SHORT = (short) 0;

  // A {@code byte} constant representing numeric zero.
  static final byte ZERO_BYTE = (byte) 0;

  ////////////////////////////////////////////////////////////////////////////////
  // PIV - Object Identifiers
  ////////////////////////////////////////////////////////////////////////////////

  /**
   * TLV tag for the PIV Data Discovery object.
   */
  static final byte ID_DATA_DISCOVERY = (byte) 0x7E;

  /**
   * MSB of the BITG (Biometric Template Group) object identifier.
   */
  static final short ID_DATA_BITG_MSB = (byte) 0x7F;

  /**
   * LSB of the BITG (Biometric Template Group) object identifier.
   */
  static final short ID_DATA_BITG_LSB = (byte) 0x61;

  /**
   * Combined short identifier for the BITG (Biometric Template Group).
   */
  static final short ID_DATA_BITG = (short) 0x7F61;

  ////////////////////////////////////////////////////////////////////////////////
  // PIV - Supported Mechanisms
  ////////////////////////////////////////////////////////////////////////////////

  /**
   * Default mechanism ID, which maps to TDEA-3Key.
   */
  static final byte ID_ALG_DEFAULT = (byte) 0x00;

  /**
   * Mechanism ID for 3-key TDEA.
   */
  static final byte ID_ALG_TDEA_3KEY = (byte) 0x03;

  /**
   * Mechanism ID for 1024-bit RSA.
   */
  static final byte ID_ALG_RSA_1024 = (byte) 0x06;

  /**
   * Mechanism ID for 2048-bit RSA.
   */
  static final byte ID_ALG_RSA_2048 = (byte) 0x07;

  /**
   * Mechanism ID for 3072-bit RSA (SP800-73-5).
   */
  static final byte ID_ALG_RSA_3072 = (byte) 0x05;

  /**
   * Mechanism ID for 4096-bit RSA (extension mechanism - 0x16 picked for Yubikey compatibility).
   */
  static final byte ID_ALG_RSA_4096 = (byte) 0x16;

  /**
   * Mechanism ID for 128-bit AES.
   */
  static final byte ID_ALG_AES_128 = (byte) 0x08;

  /**
   * Mechanism ID for 192-bit AES.
   */
  static final byte ID_ALG_AES_192 = (byte) 0x0A;

  /**
   * Mechanism ID for 256-bit AES.
   */
  static final byte ID_ALG_AES_256 = (byte) 0x0C;

  /**
   * Mechanism ID for ECC using the P-256 curve.
   */
  static final byte ID_ALG_ECC_P256 = (byte) 0x11;

  /**
   * Mechanism ID for ECC using the P-384 curve.
   */
  static final byte ID_ALG_ECC_P384 = (byte) 0x14;

  /**
   * Mechanism ID for ECC-based Secure Messaging using P256+SHA256.
   */
  static final byte ID_ALG_ECC_CS2 = (byte) 0x27;

  /**
   * Mechanism ID for ECC-based Secure Messaging using P384+SHA384.
   */
  static final byte ID_ALG_ECC_CS7 = (byte) 0x2E;

  ////////////////////////////////////////////////////////////////////////////////
  // PIV - Card Holder Verification Methods
  ////////////////////////////////////////////////////////////////////////////////

  // Global PIN authentication method ID.
  static final byte ID_AUTH_GLOBAL_PIN = (byte) 0x00;

  // Local PIN authentication method ID.
  static final byte ID_AUTH_LOCAL_PIN = (byte) 0x80;

  // PUK authentication method ID.
  static final byte ID_AUTH_PUK = (byte) 0x81;

  // Primary OCC (On-Card Comparison) authentication method ID.
  static final byte ID_AUTH_OCC_PRI = (byte) 0x96;

  // Secondary OCC (On-Card Comparison) authentication method ID.
  static final byte ID_AUTH_OCC_SEC = (byte) 0x97;

  // Pairing code authentication method ID.
  static final byte ID_AUTH_PAIRING_CODE = (byte) 0x98;

  ////////////////////////////////////////////////////////////////////////////////
  // TLV construction values
  ////////////////////////////////////////////////////////////////////////////////

  // Minimum length of an object identifier.
  static final short OBJECT_ID_MIN_LENGTH = (short) 1;

  // Maximum length of an object identifier.
  static final short OBJECT_ID_MAX_LENGTH = (short) 3;

  // Maximum value for a key identifier.
  static final int KEY_ID_MAX_VALUE = 255;

  // Maximum value for a verifier identifier.
  static final int VERIFIER_ID_MAX_VALUE = 255;

  // Common tags

  // Tag for the object identifier.
  static final byte TAG_OBJECT_ID = (byte) 0x8B;

  // Tag for the contact mode.
  static final byte TAG_MODE_CONTACT = (byte) 0x8C;

  // Tag for the contactless mode.
  static final byte TAG_MODE_CONTACTLESS = (byte) 0x8D;

  // Data Objects and Key Tags

  // Tag for the administrator key.
  static final byte TAG_ADMIN_KEY = (byte) 0x91;

  // Key Tags

  // Tag for the key mechanism.
  static final byte TAG_KEY_MECHANISM = (byte) 0x8E;

  // Tag for the key role.
  static final byte TAG_KEY_ROLE = (byte) 0x8F;

  // Tag for the key attribute.
  static final byte TAG_KEY_ATTRIBUTE = (byte) 0x90;

  // Pin Tags

  // Tag for the minimum PIN length.
  static final byte TAG_PIN_MIN_LENGTH = (byte) 0x8E;

  // Tag for the maximum PIN length.
  static final byte TAG_PIN_MAX_LENGTH = (byte) 0x8F;

  // Tag for the number of retries allowed in contact mode.
  static final byte TAG_PIN_RETRIES_CONTACT = (byte) 0x90;

  // Tag for the number of retries allowed in contactless mode.
  static final byte TAG_PIN_RETRIES_CONTACTLESS = (byte) 0x91;

  // Tag specifying character set rules for the PIN.
  static final byte TAG_PIN_RULE_CHARSET = (byte) 0x92;

  // Tag specifying history rules for the PIN.
  static final byte TAG_PIN_RULE_HISTORY = (byte) 0x93;

  // Tag specifying sequence rules for the PIN.
  static final byte TAG_PIN_RULE_SEQUENCE = (byte) 0x94;

  // Tag specifying repetition rules for the PIN.
  static final byte TAG_PIN_RULE_REPEAT = (byte) 0x95;

  // Tag specifying update restrictions for the PIN.
  static final byte TAG_PIN_RESTRICT_UPDATE = (byte) 0x96;

  // Operation Type Tags

  // Tag for creating a container operation.
  static final byte TAG_OP_CREATE_CONTAINER = (byte) 0x64;

  // Tag for creating a verifier operation.
  static final byte TAG_OP_CREATE_VERIFIER = (byte) 0x65;

  // Tag for creating a key operation.
  static final byte TAG_OP_CREATE_KEY = (byte) 0x66;

  // Tag for updating a configuration operation.
  static final byte TAG_OP_UPDATE_CONFIG = (byte) 0x68;

   // Tag for deleting a data object (container) operation.
   static final byte TAG_OP_DELETE_OBJECT = (byte) 0x69;
 
   // Tag for deleting a verifier (PIN/PUK) operation.
   static final byte TAG_OP_DELETE_PIN = (byte) 0x6A;
 
   // Tag for deleting a key operation.
   static final byte TAG_OP_DELETE_KEY = (byte) 0x6B;

  // Tag for securing the applet (non-constructed tag).
  static final byte TAG_OP_SECURE_APPLET = (byte) 0x5F;

  // Tag for bulk requests.
  static final byte TAG_OP_BULK_REQUEST = (byte) 0x7E;

  ////////////////////////////////////////////////////////////////////////////////
  // Custom Error Constants
  ////////////////////////////////////////////////////////////////////////////////

  // Status word indicating an invalid value for an operation in the PUT DATA command.
  static final short SW_PUT_DATA_OP_INVALID_VALUE = (short) 0x6E14;

  // Status word indicating a missing identifier in the PUT DATA command.
  static final short SW_PUT_DATA_ID_MISSING = (short) 0x6E15;

  // Status word indicating an invalid length for an identifier in the PUT DATA command.
  static final short SW_PUT_DATA_ID_INVALID_LENGTH = (short) 0x6E16;

  // Status word indicating an invalid value for an identifier in the PUT DATA command.
  static final short SW_PUT_DATA_ID_INVALID_VALUE = (short) 0x6E28;

  // Status word indicating a missing contact mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACT_MISSING = (short) 0x6E17;

  // Status word indicating an invalid length for the contact mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_LENGTH = (short) 0x6E18;

  // Status word indicating an invalid value for the contact mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACT_INVALID_VALUE = (short) 0x6E19;

  // Status word indicating a missing contactless mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACTLESS_MISSING = (short) 0x6E1A;

  // Status word indicating an invalid length for the contactless mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_LENGTH = (short) 0x6E1B;

  // Status word indicating an invalid value for the contactless mode in the PUT DATA command.
  static final short SW_PUT_DATA_MODE_CONTACTLESS_INVALID_VALUE = (short) 0x6E1C;

  // Status word indicating an invalid length for the administrator key in the PUT DATA command.
  static final short SW_PUT_DATA_ADMIN_KEY_INVALID_LENGTH = (short) 0x6E1D;

  // Status word indicating a missing key mechanism in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_MECHANISM_MISSING = (short) 0x6E1E;

  // Status word indicating an invalid length for the key mechanism in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_MECHANISM_INVALID = (short) 0x6E1F;

  // Status word indicating a missing key role in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_ROLE_MISSING = (short) 0x6E20;

  // Status word indicating an invalid length for the key role in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_ROLE_INVALID_LENGTH = (short) 0x6E21;

  // Status word indicating a missing key attribute in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_ATTR_MISSING = (short) 0x6E22;

  // Status word indicating an invalid length for the key attribute in the PUT DATA command.
  static final short SW_PUT_DATA_KEY_ATTR_INVALID_LENGTH = (short) 0x6E23;

  // Status word indicating an invalid value for the configuration in the PUT DATA command.
  static final short SW_PUT_DATA_CONFIG_INVALID_VALUE = (short) 0x6E26;

  // Status word indicating that the object already exists.
  static final short SW_PUT_DATA_OBJECT_EXISTS = (short) 0x6E27;

  // Status word indicating an invalid minimum PIN length.
  static final short SW_PUT_DATA_PIN_INVALID_MIN_LENGTH = (short) 0x6E29;

  // Status word indicating an invalid maximum PIN length.
  static final short SW_PUT_DATA_PIN_INVALID_MAX_LENGTH = (short) 0x6E2A;

  // Status word indicating an invalid number of PIN retries in contact mode.
  static final short SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACT = (short) 0x6E2B;

  // Status word indicating an invalid number of PIN retries in contactless mode.
  static final short SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACTLESS = (short) 0x6E2C;

  // Status word indicating invalid character set rules for the PIN.
  static final short SW_PUT_DATA_PIN_INVALID_RULE_CHARSET = (short) 0x6E2D;

  // Status word indicating invalid history rules for the PIN.
  static final short SW_PUT_DATA_PIN_INVALID_RULE_HISTORY = (short) 0x6E2E;

  // Status word indicating invalid sequence rules for the PIN.
  static final short SW_PUT_DATA_PIN_INVALID_RULE_SEQUENCE = (short) 0x6E2F;

  // Status word indicating invalid repetition rules for the PIN.
  static final short SW_PUT_DATA_PIN_INVALID_RULE_REPEAT = (short) 0x6E30;

  // NOTE: Remember the values above are out-of-order, don't duplicate when making new ones!

  ////////////////////////////////////////////////////////////////////////////////
  // PIV STANDARD IDENTIFIERS
  ////////////////////////////////////////////////////////////////////////////////

  // Tag for the General Authenticate template.
  static final byte TAG_AUTH_TEMPLATE = (byte) 0x7C;

  // Tag for the witness field in General Authenticate.
  static final byte TAG_AUTH_WITNESS = (byte) 0x80;

  // Tag for the challenge field in General Authenticate.
  static final byte TAG_AUTH_CHALLENGE = (byte) 0x81;

  // Tag for the challenge response field in General Authenticate.
  static final byte TAG_AUTH_CHALLENGE_RESPONSE = (byte) 0x82;

  // Tag for the exponentiation field in General Authenticate.
  static final byte TAG_AUTH_EXPONENTIATION = (byte) 0x85;

  ////////////////////////////////////////////////////////////////////////////////
  // ISO 7816 STATUS WORD RESPONSES
  ////////////////////////////////////////////////////////////////////////////////

  // Status word used for reporting the number of remaining PIN retries.
  static final short SW_RETRIES_REMAINING = (short) 0x63C0;
  
  // Status word used for reporting the Crypto Algorithm Self-Test has failed (taken from JCOP) */
  static final short SW_CAST_FAILURE = (short) 0x66A7;
  
  // Status word used for reporting the Operator Integrity Check has failed */
  static final short SW_OPERATOR_CHECK_FAILURE = (short) 0x66B7;

  ////////////////////////////////////////////////////////////////////////////////
  // PIV ADMINISTRATIVE ERROR CONSTANTS
  ////////////////////////////////////////////////////////////////////////////////

  // Status word for referencing an invalid PIN or not found reference.
  static final short SW_REFERENCE_NOT_FOUND = (short) 0x6A88;
}
