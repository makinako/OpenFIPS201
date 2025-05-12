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

import javacard.framework.ISOException;
import javacard.framework.PINException;

abstract class PIVVerifier extends PIVObject {

  // Indicates the verifier has had no value set and therefore cannot be used
  static final byte STATE_UNINITIALISED = (byte) 0x00;

  // Indicates the verifier has been initialised with a value and may be used
  static final byte STATE_INITIALISED = (byte) 0x01;

  // PERSISTENT - Tracks the internal state
  protected byte state;

  protected PIVVerifier(int id, byte modeContact, byte modeContactless) {
    super(id, modeContact, modeContactless);

    // PRE-CONDITION: For verifiers, the access modes can only be ALWAYS or NEVER
    if ((modeContact & ACCESS_MODE_ALWAYS) != ACCESS_MODE_ALWAYS && modeContact != ACCESS_MODE_NEVER) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACT_INVALID_VALUE);
    }
    if ((modeContactless & ACCESS_MODE_ALWAYS) != ACCESS_MODE_ALWAYS && modeContactless != ACCESS_MODE_NEVER) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_VALUE);
    }

    // PRE-CONDITION: For verifiers, at least one mode must be accessible
    if ((modeContact & ACCESS_MODE_ALWAYS) == ACCESS_MODE_NEVER
        && (modeContactless & ACCESS_MODE_ALWAYS) == ACCESS_MODE_NEVER) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACT_INVALID_VALUE);
    }

    // PRE-CONDITION: The contactless mode may only be set to ALWAYS if the SM mode is also required.
    // FIPS: This is a FIPS_APPROVED requirement that prevents authentication data from being entered
    // over a wireless interface (AS09.18).
    if (Config.FIPS_APPROVED_MODE && (modeContactless & ACCESS_MODE_ALWAYS) == ACCESS_MODE_ALWAYS
        && (modeContactless & ACCESS_MODE_SM) != ACCESS_MODE_SM) {
      ISOException.throwIt(Constants.SW_PUT_DATA_MODE_CONTACTLESS_INVALID_VALUE);
    }
  }

  @Override
  void clear() {
    //
    // There is no way to erase/zeorise an OwnerPIN object, so we just set our state
    // so that it may not be used until set.
    //
    state = STATE_UNINITIALISED;
  }

  @Override
  boolean isInitialised() {
    // NOTE:
    // We just check that the INITIALISED bit is set, as this may be implied by other states
    return (state & STATE_INITIALISED) == STATE_INITIALISED;
  }

  @Override
  byte getAdminKey() {
    // PIN's do not have administrative keys for management
    return Constants.ZERO_BYTE;
  }

  /*
   * Returns true if the supplied id is one of the known PIV verification identifiers.
   */
  static boolean isVerifierId(byte id) {
    return (id == Constants.ID_AUTH_LOCAL_PIN || id == Constants.ID_AUTH_GLOBAL_PIN || id == Constants.ID_AUTH_PUK
        || id == Constants.ID_AUTH_PAIRING_CODE || id == Constants.ID_AUTH_OCC_PRI || id == Constants.ID_AUTH_OCC_SEC);
  }

  boolean getRestrictUpdate() {
    return false; // By default, update is permitted
  }

  abstract byte getMinLength();

  abstract byte getMaxLength();

  /***
   * Returns the number of tries remaining on the contact interface
   * 
   * @return The number of remaining attempts on the contact interface
   */
  abstract byte getContactTriesRemaining();

  /***
   * Returns the number of tries remaining on the contactless interface
   * 
   * @return The number of remaining attempts on the contactless interface
   */
  abstract byte getContactlessTriesRemaining();

  abstract boolean check(byte[] buffer, short offset, short length)
      throws ArrayIndexOutOfBoundsException, NullPointerException;

  abstract boolean isValidated();

  abstract void reset();

  abstract byte getTryLimit();

  abstract void update(byte[] buffer, short offset, short length) throws PINException;
  

  /*
   * Verifier Factory
   */
  static PIVVerifier createVerifier(int id, byte modeContact, byte modeContactless, TLVReader reader) throws ISOException {

    //
    // PIN PARAMETERS
    //

    // PRE-CONDITION: Make sure the id is within the range for a key
    if (id > Constants.VERIFIER_ID_MAX_VALUE) {
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_INVALID_LENGTH);
    }

    // PRE-CONDITION: The 'PIN MIN LENGTH' tag MUST be present with length 1
    if (!reader.match(Constants.TAG_PIN_MIN_LENGTH) || reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_MIN_LENGTH);
    }
    byte minLength = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION: The 'PIN MAX LENGTH' tag MUST be present with length 1
    if (!reader.match(Constants.TAG_PIN_MAX_LENGTH) || reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_MAX_LENGTH);
    }
    byte maxLength = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION: minLength must not exceed maxLength
    if (minLength > maxLength) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_MIN_LENGTH);
    }

    // PRE-CONDITION: minLength must not be lower than the hard limit
    byte effectiveMinLimit = Config.FIPS_APPROVED_MODE ? PIVVerifierPIN.LIMIT_MIN_LENGTH_FIPS
        : PIVVerifierPIN.LIMIT_MIN_LENGTH;
    if (minLength < effectiveMinLimit) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_MIN_LENGTH);
    }

    // PRE-CONDITION: maxLength must not be higher than the hard limit
    if (maxLength > PIVVerifierPIN.LIMIT_MAX_LENGTH) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_MAX_LENGTH);
    }

    // PRE-CONDITION: The 'PIN RETRIES CONTACT' tag MAY be present
    if (!reader.match(Constants.TAG_PIN_RETRIES_CONTACT) || reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACT);
    }
    byte retriesContact = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 5: The 'PIN RETRIES CONTACTLESS' tag MAY be present
    if (!reader.match(Constants.TAG_PIN_RETRIES_CONTACTLESS) || reader.getLength() != (short) 1) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACTLESS);
    }
    byte retriesContactless = reader.toByte();
    reader.moveNext();

    // PRE-CONDITION 6: retriesContactless must not exceed retriesContact
    if (retriesContactless > retriesContact) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACTLESS);
    }

    // PRE-CONDITION 7: retriesContact must be within 0 and the hard limit
    short hardRetryLimit = (Config.FIPS_APPROVED_MODE) ? PIVVerifierPIN.LIMIT_RETRIES_FIPS
        : PIVVerifierPIN.LIMIT_RETRIES;

    if (retriesContact < (byte) 0 || retriesContact > hardRetryLimit) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACT);
    }

    // PRE-CONDITION 8: retriesContactless must be within 0 and the hard limit
    if (retriesContactless < (byte) 0 || retriesContactless > hardRetryLimit) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RETRIES_CONTACTLESS);
    }

    // PRE-CONDITION 9: The 'PIN RULE - CHARSET' tag MAY be present
    byte charset = PIVVerifierPIN.CHARSET_NUMERIC;
    if (reader.match(Constants.TAG_PIN_RULE_CHARSET)) {
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_CHARSET);
      }
      charset = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 10: The value must be one of the valid charset options
    if (charset != PIVVerifierPIN.CHARSET_NUMERIC && charset != PIVVerifierPIN.CHARSET_ALPHA
        && charset != PIVVerifierPIN.CHARSET_ALPHA_INVARIANT && charset != PIVVerifierPIN.CHARSET_RAW) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_CHARSET);
    }

    // PRE-CONDITION 11: If CHARSET_RAW, the minimum and maximum values must be equal
    if (charset == PIVVerifierPIN.CHARSET_RAW && minLength != maxLength) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_CHARSET);
    }

    // PRE-CONDITION 12: The 'PIN RULE - HISTORY' tag MAY be present
    byte history = 0;
    if (reader.match(Constants.TAG_PIN_RULE_HISTORY)) {
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_HISTORY);
      }
      history = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 13: The value must be within the limits
    if (history < (byte) 0 || history > PIVVerifierPIN.LIMIT_HISTORY) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_HISTORY);
    }

    // PRE-CONDITION 14: The 'PIN RULE - SEQUENCE' tag MAY be present
    byte ruleSequence = 0;
    if (reader.match(Constants.TAG_PIN_RULE_SEQUENCE)) {
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_SEQUENCE);
      }
      ruleSequence = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 15: The value must be within the limits
    if (ruleSequence < (byte) 0 || ruleSequence > PIVVerifierPIN.LIMIT_MAX_LENGTH) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_SEQUENCE);
    }

    // PRE-CONDITION 16: The 'PIN RULE - REPEAT' tag MAY be present
    byte ruleRepeat = 0;
    if (reader.match(Constants.TAG_PIN_RULE_REPEAT)) {
      if (reader.getLength() != (short) 1) {
        ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_REPEAT);
      }
      ruleRepeat = reader.toByte();
      reader.moveNext();
    }

    // PRE-CONDITION 17: The value must be within the limits
    if (ruleRepeat < (byte) 0 || ruleRepeat > PIVVerifierPIN.LIMIT_MAX_LENGTH) {
      ISOException.throwIt(Constants.SW_PUT_DATA_PIN_INVALID_RULE_REPEAT);
    }

    // PRE-CONDITION 18: The 'RESTRICT UPDATE' tag MAY be present
    byte restrictUpdate = Constants.FALSE_BYTE;
    if (reader.match(Constants.TAG_PIN_RESTRICT_UPDATE)) {
      restrictUpdate = (reader.toByte() == 0) ? Constants.FALSE_BYTE : Constants.TRUE_BYTE;
      reader.moveNext();
    }

    switch ((byte) id) {

    case Constants.ID_AUTH_LOCAL_PIN:
    case Constants.ID_AUTH_PAIRING_CODE:
    case Constants.ID_AUTH_PUK:
      return new PIVVerifierLocalPIN(id, modeContact, modeContactless, minLength, maxLength, retriesContact,
          retriesContactless, charset, history, ruleSequence, ruleRepeat, restrictUpdate);

    case Constants.ID_AUTH_GLOBAL_PIN:
      return new PIVVerifierCVMPIN(id, modeContact, modeContactless, minLength, maxLength, retriesContact,
          retriesContactless, charset, history, ruleSequence, ruleRepeat, restrictUpdate);

    default:
      ISOException.throwIt(Constants.SW_PUT_DATA_ID_INVALID_VALUE);
      return null; // Keep compiler happy
    }
  }
  
}