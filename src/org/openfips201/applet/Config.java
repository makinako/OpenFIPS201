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

/**
 * Defines all configurable elements of the PIV applet in one place. This allows customisation of
 * the data and key file system as well as controlling the behaviour of the applet.
 */
final class Config {

  //
  // BUILD VERSION INFORMATION
  // This information is updated prior to release build. It is not updated automatically yet and
  // has no causal relationship with commits, so the value should only be trusted when read from
  // a release.
  //
  static final byte[] APPLICATION_NAME =
      new byte[] {'O', 'p', 'e', 'n', 'F', 'I', 'P', 'S', '2', '0', '1'};
  static final short LENGTH_APPLICATION_NAME = (short) 11;
  static final byte VERSION_MAJOR = (byte) 1;
  static final byte VERSION_MINOR = (byte) 10;
  static final byte VERSION_REVISION = (byte) 2;
  static final byte VERSION_DEBUG = (byte) 0; // If set to 1, this build is considered DEBUG

  ///////////////////////////////////////////////////////////////////////////
  //
  // PIV CONSTANT DEFINITIONS
  //
  // This section defines the PIV constant values for a number of different
  // data objects. They should be generally not changed, or changed with
  // great care.
  //
  ///////////////////////////////////////////////////////////////////////////

  // The default value for the special DISCOVERY object
  static final byte[] TEMPLATE_DISCOVERY =
      new byte[] {

        /// 2 bytes - Discovery Object (TAG '7E')
        (byte) 0x7E,
        (byte) 0x12,

        // 2 + 11 bytes - PIV Card Application AID (TAG '4F')
        (byte) 0x4F,
        (byte) 0x0B,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x10,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,

        // 3 + 2 bytes - PIN Usage Policy
        (byte) 0x5F,
        (byte) 0x2F,
        (byte) 0x02,
        // NOTE: The remaining 2 policy bytes are set
        (byte) 0x00,
        (byte) 0x00
      };

  /// The default value for the PIV Application Property Template (APT), which is returned
  /// when the applet is selected (this represents the FCI parameter as per ISO-7816)
  protected static final byte[] TEMPLATE_APT =
      new byte[] {

        // 2 bytes - Application Property Template (TAG '61')
        (byte) 0x61,
        (byte) 0x81,
        (byte) 0x8F,

        // 2 + 11 bytes - Application identifier of application (TAG '4F')
        (byte) 0x4F,
        (byte) 0x0B,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x10,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,

        // 2 + 7 bytes - Coexistent Tag Allocation Authority (TAG '79')
        (byte) 0x79,
        (byte) 0x07,
        (byte) 0x4F,
        (byte) 0x05,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,

        // 2 + 11 bytes - Application label
        // OpenFIPS201
        (byte) 0x50,
        (byte) 0x0B,
        'O',
        'p',
        'e',
        'n',
        'F',
        'I',
        'P',
        'S',
        '2',
        '0',
        '1',

        // 3 + 73 bytes - Uniform resource locator
        // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
        (byte) 0x5F,
        (byte) 0x50,
        (byte) 0x49,
        'h',
        't',
        't',
        'p',
        ':',
        '/',
        '/',
        'n',
        'v',
        'l',
        'p',
        'u',
        'b',
        's',
        '.',
        'n',
        'i',
        's',
        't',
        '.',
        'g',
        'o',
        'v',
        '/',
        'n',
        'i',
        's',
        't',
        'p',
        'u',
        'b',
        's',
        '/',
        'S',
        'p',
        'e',
        'c',
        'i',
        'a',
        'l',
        'P',
        'u',
        'b',
        'l',
        'i',
        'c',
        'a',
        't',
        'i',
        'o',
        'n',
        's',
        '/',
        'N',
        'I',
        'S',
        'T',
        '.',
        'S',
        'P',
        '.',
        '8',
        '0',
        '0',
        '-',
        '7',
        '3',
        '-',
        '4',
        '.',
        'p',
        'd',
        'f',

        // 2 + 24 - Cryptographic Algorithm Identifier Template (Tag 'AC')
        (byte) 0xAC,
        (byte) 0x1E,

        // Supported mechanisms
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_DEFAULT,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_TDEA_3KEY,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_128,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_192,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_256,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_RSA_1024,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_RSA_2048,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_ECC_P256,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_ECC_P384,

        // Object identifier
        (byte) 0x06,
        (byte) 0x01,
        (byte) 0x00
      };

  ////////////////////////////////////////////////////////////////////////////////
  //
  // Configuration Elements
  //
  // This section defines all configurable parameters within the OpenFIPS201
  // applet. The numbering system here defines the internal storage (array offset)
  // for each parameter, not the ASN.1 definition.
  //
  // The takeaway from this is, don't rely at all on the integer value of these
  // constants to provide meaning across versions, use the ASN.1 instead!
  ////////////////////////////////////////////////////////////////////////////////

  // The number of records in the configuration table.
  private static final short LENGTH_CONFIG = (short) 27;

  // PIN Policy

  static final byte CONFIG_PIN_ENABLE_LOCAL = (byte) 0;
  static final byte CONFIG_PIN_ENABLE_GLOBAL = (byte) 1;
  static final byte CONFIG_PIN_PREFER_GLOBAL = (byte) 2;
  static final byte CONFIG_PIN_PERMIT_CONTACTLESS = (byte) 3;
  static final byte CONFIG_PIN_MIN_LENGTH = (byte) 4;
  static final byte CONFIG_PIN_MAX_LENGTH = (byte) 5;
  static final byte CONFIG_PIN_RETRIES_CONTACT = (byte) 6;
  static final byte CONFIG_PIN_RETRIES_CONTACTLESS = (byte) 7;
  static final byte CONFIG_PIN_CHARSET = (byte) 8;
  static final byte CONFIG_PIN_HISTORY = (byte) 9;
  static final byte CONFIG_PIN_RULE_SEQUENCE = (byte) 10;
  static final byte CONFIG_PIN_RULE_DISTINCT = (byte) 11;

  // PUK Policy

  static final byte CONFIG_PUK_ENABLED = (byte) 12;
  static final byte CONFIG_PUK_PERMIT_CONTACTLESS = (byte) 13;
  static final byte CONFIG_PUK_LENGTH = (byte) 14;
  static final byte CONFIG_PUK_RETRIES_CONTACT = (byte) 15;
  static final byte CONFIG_PUK_RETRIES_CONTACTLESS = (byte) 16;
  static final byte CONFIG_PUK_RESTRICT_UPDATE = (byte) 17;

  // VCI Policy

  static final byte CONFIG_VCI_MODE = (byte) 18;
  static final byte CONFIG_OCC_MODE = (byte) 19;

  // Options
  static final byte OPTION_RESTRICT_CONTACTLESS_GLOBAL = (byte) 20;
  static final byte OPTION_RESTRICT_CONTACTLESS_ADMIN = (byte) 21;
  static final byte OPTION_RESTRICT_ENUMERATION = (byte) 22;
  static final byte OPTION_RESTRICT_SINGLE_KEY = (byte) 23;
  static final byte OPTION_IGNORE_CONTACTLESS_ACL = (byte) 24;
  static final byte OPTION_READ_EMPTY_DATA_OBJECT = (byte) 25;
  static final byte OPTION_USE_RSA_CRT = (byte) 26;

  //
  // Defaults and Limits
  //
  static final byte LIMIT_PIN_MIN_LENGTH = (byte) 4;
  static final byte LIMIT_PIN_MAX_LENGTH = (byte) 16;
  static final byte LIMIT_PIN_MAX_RETRIES = (byte) 15;
  static final byte LIMIT_PIN_HISTORY = (byte) 12;

  static final byte LIMIT_PUK_MIN_LENGTH = (byte) 6;
  static final byte LIMIT_PUK_MAX_LENGTH = (byte) 16;
  static final byte LIMIT_PUK_MAX_RETRIES = (byte) 15;

  private static final byte DEFAULT_PIN_ENABLE_LOCAL = TLV.TRUE;
  private static final byte DEFAULT_PIN_MIN_LENGTH = (byte) 6;
  private static final byte DEFAULT_PIN_MAX_LENGTH = (byte) 8;
  private static final byte DEFAULT_PIN_RETRIES_CONTACT = (byte) 6;
  private static final byte DEFAULT_PIN_RETRIES_CONTACTLESS = (byte) 5;

  private static final byte DEFAULT_PUK_ENABLED = TLV.TRUE;
  private static final byte DEFAULT_PUK_LENGTH = (byte) 8;
  private static final byte DEFAULT_PUK_RETRIES_CONTACT = (byte) 10;
  private static final byte DEFAULT_PUK_RETRIES_CONTACTLESS = (byte) 9;

  //
  // Enumeration - PIN Mode
  //
  static final byte PIN_MODE_DISABLED = (byte) 0;
  static final byte PIN_MODE_LOCAL_ONLY = (byte) 1;
  static final byte PIN_MODE_GLOBAL_ONLY = (byte) 2;
  static final byte PIN_MODE_LOCAL_PREFERRED = (byte) 3;
  static final byte PIN_MODE_GLOBAL_PREFERRED = (byte) 4;

  //
  // Enumeration - PIN Character Set
  //
  static final byte PIN_CHARSET_NUMERIC = (byte) 0;
  static final byte PIN_CHARSET_ALPHA = (byte) 1;
  static final byte PIN_CHARSET_ALPHA_INVARIANT = (byte) 2;
  static final byte PIN_CHARSET_RAW = (byte) 3;

  //
  // Enumeration - VCI Mode
  //
  static final byte VCI_MODE_DISABLED = (byte) 0;
  static final byte VCI_MODE_ENABLED = (byte) 1;
  static final byte VCI_MODE_PAIRING_CODE = (byte) 2;

  //
  // Enumeration - OCC Mode
  //
  static final byte OCC_MODE_DISABLED = (byte) 0;

  //
  // ASN.1 TAGS - Constructed (Container)
  //
  private static final byte TAG_PIN_POLICY = (byte) 0xA0;
  private static final byte TAG_PUK_POLICY = (byte) 0xA1;
  private static final byte TAG_VCI_POLICY = (byte) 0xA2;
  private static final byte TAG_OCC_POLICY = (byte) 0xA3;
  private static final byte TAG_OPTIONS = (byte) 0xA4;

  //
  // ASN.1 TAGS - Primitive (Elements)
  //
  private static final byte TAG_PIN_ENABLE_LOCAL = (byte) 0x80;
  private static final byte TAG_PIN_ENABLE_GLOBAL = (byte) 0x81;
  private static final byte TAG_PIN_PREFER_GLOBAL = (byte) 0x82;
  private static final byte TAG_PIN_PERMIT_CONTACTLESS = (byte) 0x83;
  private static final byte TAG_PIN_MIN_LENGTH = (byte) 0x84;
  private static final byte TAG_PIN_MAX_LENGTH = (byte) 0x85;
  private static final byte TAG_PIN_RETRIES_CONTACT = (byte) 0x86;
  private static final byte TAG_PIN_RETRIES_CONTACTLESS = (byte) 0x87;
  private static final byte TAG_PIN_CHARSET = (byte) 0x88;
  private static final byte TAG_PIN_HISTORY = (byte) 0x89;
  private static final byte TAG_PIN_RULE_SEQUENCE = (byte) 0x8A;
  private static final byte TAG_PIN_RULE_DISTINCT = (byte) 0x8B;

  private static final byte TAG_PUK_ENABLED = (byte) 0x80;
  private static final byte TAG_PUK_PERMIT_CONTACTLESS = (byte) 0x81;
  private static final byte TAG_PUK_LENGTH = (byte) 0x82;
  private static final byte TAG_PUK_RETRIES_CONTACT = (byte) 0x83;
  private static final byte TAG_PUK_RETRIES_CONTACTLESS = (byte) 0x84;
  private static final byte TAG_PUK_RESTRICT_UPDATE = (byte) 0x85;

  private static final byte TAG_VCI_MODE = (byte) 0x80;
  private static final byte TAG_OCC_MODE = (byte) 0x80;

  private static final byte TAG_RESTRICT_CONTACTLESS_GLOBAL = (byte) 0x80;
  private static final byte TAG_RESTRICT_CONTACTLESS_ADMIN = (byte) 0x81;
  private static final byte TAG_RESTRICT_ENUMERATION = (byte) 0x82;
  private static final byte TAG_RESTRICT_SINGLE_KEY = (byte) 0x83;
  private static final byte TAG_IGNORE_CONTACTLESS_ACL = (byte) 0x84;
  private static final byte TAG_READ_EMPTY_DATA_OBJECT = (byte) 0x85;
  private static final byte TAG_USE_RSA_CRT = (byte) 0x86;

  //
  // Storage members
  //

  // PERSISTENT - Internal configuration table
  private final byte[] config;

  Config() {

    config = new byte[LENGTH_CONFIG];

    //
    // DEFAULT VALUES
    //
    // NOTE:
    // Most configuration values are left at their initialised (zero/false) value,
    // so the defaults below represent only those that required explicit initialisation
    // in order to achieve compliance with the NIST FIPS 201 or NIST SP 800-73-4.

    // PIN
    config[CONFIG_PIN_ENABLE_LOCAL] = DEFAULT_PIN_ENABLE_LOCAL;
    config[CONFIG_PIN_MIN_LENGTH] = DEFAULT_PIN_MIN_LENGTH;
    config[CONFIG_PIN_MAX_LENGTH] = DEFAULT_PIN_MAX_LENGTH;
    config[CONFIG_PIN_RETRIES_CONTACT] = DEFAULT_PIN_RETRIES_CONTACT;
    config[CONFIG_PIN_RETRIES_CONTACTLESS] = DEFAULT_PIN_RETRIES_CONTACTLESS;

    // PUK
    config[CONFIG_PUK_ENABLED] = DEFAULT_PUK_ENABLED;
    config[CONFIG_PUK_LENGTH] = DEFAULT_PUK_LENGTH;
    config[CONFIG_PUK_RETRIES_CONTACT] = DEFAULT_PUK_RETRIES_CONTACT;
    config[CONFIG_PUK_RETRIES_CONTACTLESS] = DEFAULT_PUK_RETRIES_CONTACTLESS;
  }

  byte readValue(byte address) {
    return config[address];
  }

  boolean readFlag(byte address) {
    return (config[address] != (byte) 0);
  }

  byte getIntermediatePINRetries() {
    return (byte) (config[CONFIG_PIN_RETRIES_CONTACT] - config[CONFIG_PIN_RETRIES_CONTACTLESS]);
  }

  byte getIntermediatePUKRetries() {
    return (byte) (config[CONFIG_PUK_RETRIES_CONTACT] - config[CONFIG_PUK_RETRIES_CONTACTLESS]);
  }

  private void setBoolean(byte address, byte value) {
    config[address] = (value != (byte) 0 ? TLV.TRUE : TLV.FALSE);
  }

  void update(TLVReader reader) {

    // NOTES:
    // - Due to all configuration parameters being optional, pre-conditions are evaluated
    //   in each section on-the-fly rather than all prior to execution.
    // - To save on validation code, any boolean value is just stored as a byte and any
    //   non-zero value is considered True.

    //
    // PIN POLICY
    //
    if (reader.match(TAG_PIN_POLICY)) {

      // Sanity check for empty constructed tag
      if (reader.isNull()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // Enable Local
      if (reader.match(TAG_PIN_ENABLE_LOCAL)) {
        setBoolean(CONFIG_PIN_ENABLE_LOCAL, reader.toByte());
        reader.moveNext();
      }

      // Enable Global
      if (reader.match(TAG_PIN_ENABLE_GLOBAL)) {
        setBoolean(CONFIG_PIN_ENABLE_GLOBAL, reader.toByte());
        reader.moveNext();
      }

      // Prefer Global
      if (reader.match(TAG_PIN_PREFER_GLOBAL)) {
        setBoolean(CONFIG_PIN_PREFER_GLOBAL, reader.toByte());
        reader.moveNext();
      }

      // Permit Contactless
      if (reader.match(TAG_PIN_PERMIT_CONTACTLESS)) {
        setBoolean(CONFIG_PIN_PERMIT_CONTACTLESS, reader.toByte());
        reader.moveNext();
      }

      //
      // PIN LENGTH NOTES:
      // We need to enforce a rule where the minimum length is <= to the maximum, so we
      // record both first and evaluate at the end.
      //

      // Min Length
      boolean lengthChanged = false;
      byte minLength = config[CONFIG_PIN_MIN_LENGTH];
      if (reader.match(TAG_PIN_MIN_LENGTH)) {
        byte value = reader.toByte();
        if (value < LIMIT_PIN_MIN_LENGTH || value > LIMIT_PIN_MAX_LENGTH) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        minLength = value;
        lengthChanged = true;
        reader.moveNext();
      }

      // Max Length
      byte maxLength = config[CONFIG_PIN_MAX_LENGTH];
      if (reader.match(TAG_PIN_MAX_LENGTH)) {
        byte value = reader.toByte();
        if (value < LIMIT_PIN_MIN_LENGTH || value > LIMIT_PIN_MAX_LENGTH) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        maxLength = value;
        lengthChanged = true;
        reader.moveNext();
      }

      // Validate and update the PIN values if necessary
      if (lengthChanged) {
        if (minLength > maxLength) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_MIN_LENGTH] = minLength;
        config[CONFIG_PIN_MAX_LENGTH] = maxLength;
      }

      // Retries Contact
      if (reader.match(TAG_PIN_RETRIES_CONTACT)) {
        byte value = reader.toByte();
        if (value < (byte) 0 || value > LIMIT_PIN_MAX_RETRIES) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_RETRIES_CONTACT] = value;
        reader.moveNext();
      }

      // Retries Contactless
      if (reader.match(TAG_PIN_RETRIES_CONTACTLESS)) {
        byte value = reader.toByte();
        // Pre-condition - Boundary check
        if (value < (byte) 0 || value > LIMIT_PIN_MAX_RETRIES) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Pre-condition - Cannot be greater than RETRIES_CONTACT
        if (value > config[CONFIG_PIN_RETRIES_CONTACT]) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_RETRIES_CONTACTLESS] = value;
        reader.moveNext();
      }

      // Charset
      if (reader.match(TAG_PIN_CHARSET)) {
        byte value = reader.toByte();
        if (value < PIN_CHARSET_NUMERIC || value > PIN_CHARSET_RAW) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_CHARSET] = value;
        reader.moveNext();
      }

      // History
      if (reader.match(TAG_PIN_HISTORY)) {
        byte value = reader.toByte();
        if (value < (byte) 0 || value > LIMIT_PIN_HISTORY) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_HISTORY] = value;
        reader.moveNext();
      }

      // Rule - Sequence
      if (reader.match(TAG_PIN_RULE_SEQUENCE)) {
        byte value = reader.toByte();
        if (value < (byte) 0 || value > LIMIT_PIN_MAX_LENGTH) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_RULE_SEQUENCE] = value;
        reader.moveNext();
      }

      // Rule - Distinctiveness
      if (reader.match(TAG_PIN_RULE_DISTINCT)) {
        byte value = reader.toByte();
        if (value < (byte) 0 || value > LIMIT_PIN_MAX_LENGTH) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PIN_RULE_DISTINCT] = value;
        reader.moveNext();
      }
    }

    //
    // PUK POLICY
    //
    if (reader.match(TAG_PUK_POLICY)) {

      // Sanity check for empty constructed tag
      if (reader.isNull()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // PUK Enabled
      if (reader.match(TAG_PUK_ENABLED)) {
        setBoolean(CONFIG_PUK_ENABLED, reader.toByte());
        reader.moveNext();
      }

      // Permit Contactless
      if (reader.match(TAG_PUK_PERMIT_CONTACTLESS)) {
        setBoolean(CONFIG_PUK_PERMIT_CONTACTLESS, reader.toByte());
        reader.moveNext();
      }

      // Length
      if (reader.match(TAG_PUK_LENGTH)) {
        byte value = reader.toByte();
        if (value < LIMIT_PUK_MIN_LENGTH || value > LIMIT_PUK_MAX_LENGTH) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PUK_LENGTH] = value;
        reader.moveNext();
      }

      // Retries Contact
      if (reader.match(TAG_PUK_RETRIES_CONTACT)) {
        byte value = reader.toByte();
        if (value < (byte) 0 || value > LIMIT_PUK_MAX_RETRIES) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PUK_RETRIES_CONTACT] = value;
        reader.moveNext();
      }

      // Retries Contactless
      if (reader.match(TAG_PUK_RETRIES_CONTACTLESS)) {
        byte value = reader.toByte();
        // Pre-condition - Boundary check
        if (value < (byte) 0 || value > LIMIT_PUK_MAX_RETRIES) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        // Pre-condition - Must not be more than PUK_RETRIES_CONTACT
        if (value > config[CONFIG_PUK_RETRIES_CONTACT]) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        config[CONFIG_PUK_RETRIES_CONTACTLESS] = value;
        reader.moveNext();
      }

      // Updateable
      if (reader.match(TAG_PUK_RESTRICT_UPDATE)) {
        setBoolean(CONFIG_PUK_RESTRICT_UPDATE, reader.toByte());
        reader.moveNext();
      }
    }

    //
    // VCI POLICY
    //
    if (reader.match(TAG_VCI_POLICY)) {

      // Sanity check for empty constructed tag
      if (reader.isNull()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // Mode
      if (reader.match(TAG_VCI_MODE)) {
        // TODO: Validation
        config[CONFIG_VCI_MODE] = reader.toByte();
        reader.moveNext();
      }
    }

    //
    // OCC POLICY
    //
    if (reader.match(TAG_OCC_POLICY)) {

      // Sanity check for empty constructed tag
      if (reader.isNull()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // Mode
      if (reader.match(TAG_OCC_MODE)) {
        // TODO: Validation
        config[CONFIG_OCC_MODE] = reader.toByte();
        reader.moveNext();
      }
    }

    //
    // OPTIONS
    //
    if (reader.match(TAG_OPTIONS)) {

      // Sanity check for empty constructed tag
      if (reader.isNull()) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      reader.moveInto();

      // Restrict Contactless - Global
      if (reader.match(TAG_RESTRICT_CONTACTLESS_GLOBAL)) {
        setBoolean(OPTION_RESTRICT_CONTACTLESS_GLOBAL, reader.toByte());
        reader.moveNext();
      }

      // Restrict Contactless - Admin
      if (reader.match(TAG_RESTRICT_CONTACTLESS_ADMIN)) {
        setBoolean(OPTION_RESTRICT_CONTACTLESS_ADMIN, reader.toByte());
        reader.moveNext();
      }

      // Restrict Enumeration
      if (reader.match(TAG_RESTRICT_ENUMERATION)) {
        setBoolean(OPTION_RESTRICT_ENUMERATION, reader.toByte());
        reader.moveNext();
      }

      // Restrict Single Key
      if (reader.match(TAG_RESTRICT_SINGLE_KEY)) {
        setBoolean(OPTION_RESTRICT_SINGLE_KEY, reader.toByte());
        reader.moveNext();
      }

      // Ignore Contactless ACL
      if (reader.match(TAG_IGNORE_CONTACTLESS_ACL)) {
        setBoolean(OPTION_IGNORE_CONTACTLESS_ACL, reader.toByte());
        reader.moveNext();
      }

      // Error On Empty Data Object
      if (reader.match(TAG_READ_EMPTY_DATA_OBJECT)) {
        setBoolean(OPTION_READ_EMPTY_DATA_OBJECT, reader.toByte());
        reader.moveNext();
      }

      // Use RSA CRT
      if (reader.match(TAG_USE_RSA_CRT)) {
        setBoolean(OPTION_USE_RSA_CRT, reader.toByte());
        reader.moveNext();
      }
    }
  }
}
