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
import javacard.framework.OwnerPIN;

abstract class PIVVerifierPIN extends PIVVerifier {

  //
  // Constants
  //

  // Defaults and Limits
  static final byte LIMIT_MIN_LENGTH = (byte) 4;
  static final byte LIMIT_MIN_LENGTH_FIPS = (byte) 6;
  static final byte LIMIT_MAX_LENGTH = (byte) 16;
  static final byte LIMIT_RETRIES = (byte) 127;
  static final byte LIMIT_RETRIES_FIPS = (byte) 15;
  static final byte LIMIT_HISTORY = (byte) 12; // Based on a pin change per month

  // Enumeration - PIN Character Set
  static final byte CHARSET_NUMERIC = (byte) 0;
  static final byte CHARSET_ALPHA = (byte) 1;
  static final byte CHARSET_ALPHA_INVARIANT = (byte) 2;
  static final byte CHARSET_RAW = (byte) 3;

  // The character used for padding pin values less than the maximum length
  private static final byte PIN_PADDING_BYTE = (byte) 0xFF;

  //
  // Extended header Format (must start beyond the PIVObject headers)
  //
  protected static final short HEADER_MIN_LENGTH = (short) 2;
  protected static final short HEADER_MAX_LENGTH = (short) 3;
  protected static final short HEADER_RETRIES_CONTACT = (short) 4;
  protected static final short HEADER_RETRIES_CONTACTLESS = (short) 5;
  protected static final short HEADER_CHARSET = (short) 6;
  protected static final short HEADER_RULE_HISTORY = (short) 7;
  protected static final short HEADER_RULE_SEQUENCE = (short) 8;
  protected static final short HEADER_RULE_REPETITION = (short) 9;
  protected static final short HEADER_RESTRICT_UPDATE = (short) 10;
  protected static final short HEADER_NEXT_HISTORY = (short) 11;

  private static final short LENGTH_EXTENDED_HEADER = (short) 12;
  
  /*
   * PERSISTENT objects
   */

  // The PIN JCRE value
  private final OwnerPIN[] history;

  PIVVerifierPIN(int id, byte modeContact, byte modeContactless, byte minLength, byte maxLength, byte retriesContact,
      byte retriesContactless, byte charset, byte ruleHistory, byte ruleSequence, byte ruleRepetition, byte restrictUpdate) {
    super(id, modeContact, modeContactless);

    // If RETRIES_CONTACT has been set to 0, ensure the contactless retries are also set to 0    
    if (retriesContact == 0) {
      retriesContactless = 0;
    }

    // Set the header values
    header[HEADER_MIN_LENGTH] = minLength;
    header[HEADER_MAX_LENGTH] = maxLength;
    header[HEADER_RETRIES_CONTACT] = retriesContact;
    header[HEADER_RETRIES_CONTACTLESS] = retriesContactless;
    header[HEADER_CHARSET] = charset;
    header[HEADER_RULE_HISTORY] = ruleHistory;
    header[HEADER_RULE_SEQUENCE] = ruleSequence;
    header[HEADER_RULE_REPETITION] = ruleRepetition;
    header[HEADER_RESTRICT_UPDATE] = restrictUpdate;
   
    // Pre-allocate the PIN history
    history = new OwnerPIN[ruleHistory];
    for (short i = 0; i < history.length; i++) {
      history[i] = Platform.createPIN(LIMIT_RETRIES, maxLength);
    }
    header[HEADER_NEXT_HISTORY] = 0;      
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
    writer.write(Constants.TAG_PIN_MIN_LENGTH, header[HEADER_MIN_LENGTH]);
    writer.write(Constants.TAG_PIN_MAX_LENGTH, header[HEADER_MAX_LENGTH]);
    writer.write(Constants.TAG_PIN_RETRIES_CONTACT, header[HEADER_RETRIES_CONTACT]);
    writer.write(Constants.TAG_PIN_RETRIES_CONTACTLESS, header[HEADER_RETRIES_CONTACTLESS]);
    writer.write(Constants.TAG_PIN_RULE_CHARSET, header[HEADER_CHARSET]);
    writer.write(Constants.TAG_PIN_RULE_HISTORY, header[HEADER_RULE_HISTORY]);
    writer.write(Constants.TAG_PIN_RULE_SEQUENCE, header[HEADER_RULE_SEQUENCE]);
    writer.write(Constants.TAG_PIN_RULE_REPEAT, header[HEADER_RULE_REPETITION]);
    writer.write(Constants.TAG_PIN_RESTRICT_UPDATE, header[HEADER_RESTRICT_UPDATE]);    
    return writer.finish();
  }

  
  @Override
  byte getMinLength() {
    return header[HEADER_MIN_LENGTH];
  }

  @Override
  byte getMaxLength() {
    return header[HEADER_MAX_LENGTH];
  }

  @Override
  boolean getRestrictUpdate() {
    return (header[HEADER_RESTRICT_UPDATE] == Constants.TRUE_BYTE);
  }

  protected final void processInvariantPin(byte[] buffer, short offset, short length) {
  
    // Invariant Check    
    // NOTE: This converts any alpha chars in the input buffer to all lower-case, which will then
    // ensure it matches the actual PIN value.
    // NOTE: This must be called at update() and check() to function properly.

    // The amount to add to convert upper-case to lower-case
    final byte CONST_ALPHA_CASE_DELTA = (byte) 32;

    // Check if we can just ignore this
    if (header[HEADER_CHARSET] != CHARSET_ALPHA_INVARIANT) {
      // Nothing to do
      return;
    }
    
    // Convert all upper-case to lower-case
    short end = (short)(offset + length);
    for (short i = offset; i < end; i++) {
        if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
            buffer[i] |= CONST_ALPHA_CASE_DELTA;
        }
    }
  }

  protected final void validateRules(byte[] buffer, short offset, short length) {

    boolean passed = true;

    //
    // RULE 1 - SEQUENCE RULE (Ascending and Descending)
    //
    byte ruleSequence = header[HEADER_RULE_SEQUENCE];
    if (ruleSequence > (byte) 0) {
      byte last = (byte) 0;
      byte ascendingCount = (byte) 1;
      byte descendingCount = (byte) 1;
      byte maxAscending = (byte) 0;
      byte maxDescending = (byte) 0;

      for (short i = 0; i < length; i++) {

        byte value = buffer[(short) (offset + i)];

        // If we have reached padding bytes, we are done checking
        if (value == PIN_PADDING_BYTE) {
          break;
        }

        // HACK: We make use of the fact that the ASCII value 0h is not possible
        // for a PIN value.

        // ASCENDING TALLY
        if (last != (byte) 0 && (byte) (last + (byte) 1) == value) {
          ascendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
          ascendingCount = (byte) 1;
        }

        // DESCENDING TALLY
        if (last != (byte) 0 && (byte) (last - (byte) 1) == value) {
          descendingCount++; // Increment the counter
        } else {
          // Track our largest sequence and continue
          maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;
          descendingCount = (byte) 1;
        }

        last = value;
      }

      // Track our final counts
      maxAscending = (ascendingCount > maxAscending) ? ascendingCount : maxAscending;
      maxDescending = (descendingCount > maxDescending) ? descendingCount : maxDescending;

      if (maxAscending >= ruleSequence || maxDescending >= ruleSequence) {
        passed = false;
      }
    }

    //
    // RULE 2 - REPITITION RULE
    //
    // If the repitition rule applies (n > 0) then a PIN is rejected if any
    // single character is re-used more than [n] times.
    //

    byte ruleDistinct = header[HEADER_RULE_REPETITION];
    if (ruleDistinct > (byte) 0) {
      byte maxSingle = (byte) 0;

      short end = (short) (offset + length);
      for (short i = offset; i < end; i++) {
        byte count = (byte) 1; // Every used digit has at least 1
        for (short j = (short) (i + (short) 1); j < end; j++) {
          // If we have a padding byte, we are done checking for this digit
          if (buffer[i] == PIN_PADDING_BYTE) {
            break;
          }
          if (buffer[i] == buffer[j]) {
            count++;
          }
        }
        maxSingle = (count > maxSingle) ? count : maxSingle;
      }

      if (maxSingle >= ruleDistinct) {
        passed = false;
      }
    }

    // Done, throw if we failed
    if (!passed) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Performs data validation on an incoming PIN number to ensure that it conforms to SP800-73-4
   * Part 2 - Authentication of an Individual
   *
   * @param buffer The buffer containing the PIN
   * @param offset The offset of the PIN data
   * @param length The length of the PIN data
   * @return True if the supplied PIN conforms to the format requirements
   */
  protected final void validateFormat(byte[] buffer, short offset, short length) throws ISOException {

    // The pairing code shall be exactly 8 bytes in length and the PIV Card
    // Application PIN shall be between 6 and 8 bytes in length. If the actual
    // length of PIV Card Application PIN is less than 8 bytes it shall be
    // padded to 8 bytes with 'FF' when presented to the card command interface.
    // The 'FF' padding bytes shall be appended to the actual value of the PIN.

    // NOTE: We define the minimum and maximum lengths in configuration, but only
    // the max is checked here because of the padding requirement

    //
    // PIN processing
    //
    if (length != header[HEADER_MAX_LENGTH]) {
      // Done, throw if we failed
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // The bytes comprising the PIV Card Application PIN and pairing code shall be
    // limited to values
    // 0x30-0x39, the ASCII values for the decimal digits '0'-'9'. For example,
    // + Actual PIV Card Application PIN: '123456' or '31 32 33 34 35 36'
    // + Padded PIV Card Application PIN presented to the card command interface:
    // '31 32 33 34 35 36 FF FF'

    // The PIV Card Application shall enforce the minimum length requirement of six
    // bytes for the
    // PIV Card Application PIN (i.e., shall verify that at least the first six
    // bytes of the value
    // presented to the card command interface are in the range 0x30-0x39) as well
    // as the other
    // formatting requirements specified in this section.

    // If the Global PIN is used by the PIV Card Application, then the above
    // encoding, length,
    // padding, and enforcement of minimum PIN length requirements for the PIV Card
    // Application
    // PIN shall apply to the Global PIN.

    //
    // NOTES:
    // - OpenFIPS201 permits the following PIN character sets
    // - Default (digits 0 to 9, PIV compliant)
    // - Alpha Case Variant (all printable ascii characters, not PIV compliant)
    // - Alpha Case Invariant (all printable ascii characters, case insensitive, not
    // PIV compliant)
    // - Raw (All possible values 0 to 255, same as PUK)

    byte minPermitted;
    byte maxPermitted;

    switch (header[HEADER_CHARSET]) {
    case CHARSET_ALPHA:
    case CHARSET_ALPHA_INVARIANT:
      // NOTE: For ALPHA_INVARIANT, all letters are converted to the same case before use
      minPermitted = ' '; // 20h
      maxPermitted = '~'; // 7Eh
      break;
    case CHARSET_RAW:
      // No further processing required
      return;

    case CHARSET_NUMERIC:
    default:
      minPermitted = '0'; // 30h
      maxPermitted = '9'; // 39h
      break;
    }

    boolean passed = true;
    boolean padding = false;
    short minLength = header[HEADER_MIN_LENGTH];
    for (short i = 0; i < length; i++) {
      if (padding) {
        // Once we have reached padding, all subsequent characters must be padding
        if (buffer[offset] != PIN_PADDING_BYTE) {
          passed = false;
        }
      } else {
        // Check if we have reached our padding
        if (buffer[offset] == PIN_PADDING_BYTE) {
          if (i < minLength) {
            // RULE: The minimum PIN length has not been reached
            passed = false;
          } else {
            padding = true;
          }
        } else {
          // Range Check
          if (buffer[offset] < minPermitted || buffer[offset] > maxPermitted) {
            // RULE: The PIN character does not fall in the permissable range
            passed = false;
          }
        }
      }

      offset++;

      // No need to continue if we failed already
      if (!passed) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      }
    }
  }

  protected final void validateHistory(byte[] buffer, short offset, short length) throws ISOException {
    
    //
    // PRE-CONDITIONS 
    //
    
    // PRE-CONDITION: If history is null, it is not enabled
    if (history == null) {
      return;
    }
    
    // Check the PIN History
    //
    for (short i = 0; i < history.length; i++) {
      OwnerPIN p = history[i];

      if (p == null) {
        continue;
      }

      if (p.getTriesRemaining() == 0) {
        p.resetAndUnblock();
      }

      if (p.check(buffer, offset, (byte) length)) {
        // We have matched, fail
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }

    // If we got this far, the history check passed and we can update our history
    // Then increment and roll the next pointer
    if (history.length > 0) {
      history[header[HEADER_NEXT_HISTORY]].update(buffer, offset, (byte) length);
      header[HEADER_NEXT_HISTORY]++;
      header[HEADER_NEXT_HISTORY] = (byte) (header[HEADER_NEXT_HISTORY] % history.length);
    }
  }
}
