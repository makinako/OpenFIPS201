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
import javacard.framework.PINException;

final class PIVVerifierLocalPIN extends PIVVerifierPIN {

  /*
   * PERSISTENT objects
   */

  // The PIN JCRE value
  private final OwnerPIN pin;

  PIVVerifierLocalPIN(int id, byte modeContact, byte modeContactless, byte minLength, byte maxLength,
      byte retriesContact, byte retriesContactless, byte charset, byte ruleHistory, byte ruleSequence,
      byte ruleRepetition, byte restrictUpdate) {

    super(id, modeContact, modeContactless, minLength, maxLength, retriesContact, retriesContactless, charset,
        ruleHistory, ruleSequence, ruleRepetition, restrictUpdate);

    // Create the underlying OwnerPIN object
    if (retriesContact == 0) {
      retriesContact = PIVVerifierPIN.LIMIT_RETRIES;
    }
    
    pin = Platform.createPIN(retriesContact, maxLength);
  }

  @Override
  byte getContactTriesRemaining() {
    return pin.getTriesRemaining();
  }

  @Override
  byte getContactlessTriesRemaining() {
    // It is assumed by validation that this cannot result in a negative number
    byte delta = (byte) (header[HEADER_RETRIES_CONTACT] - header[HEADER_RETRIES_CONTACTLESS]);
    if (delta < 0 || pin.getTriesRemaining() < delta) {
      return 0;
    }
    return (byte) (pin.getTriesRemaining() - delta);
  }

  @Override
  boolean check(byte[] buffer, short offset, short length) throws ArrayIndexOutOfBoundsException, NullPointerException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: The PIN must be initialised with a value
    if (!isInitialised()) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION: - The PIN length must equal the maximum length
    if (length != header[HEADER_MAX_LENGTH]) {
      // Done, throw if we failed
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    // NOTE: Any other invalid formatting will result in decrementing the pin
    // counter, which improves resistance to number space deduction.

    //
    // EXECUTION
    //

    // Process case-invariant values first (if applicable)
    processInvariantPin(buffer, offset, length);
    
    // If the configured contact retries is zero and retries <= 1, reset automatically. 
    if (header[HEADER_RETRIES_CONTACT] == 0 && pin.getTriesRemaining() <= 1) {
      pin.resetAndUnblock();
    }
        
    return pin.check(buffer, offset, (byte)length);      
  }

  @Override
  boolean isValidated() {
    return pin.isValidated();
  }

  @Override
  void reset() {
    pin.reset();
  }

  @Override
  byte getTryLimit() {
    return header[HEADER_RETRIES_CONTACT];
  }

  @Override
  void update(byte[] buffer, short offset, short length) throws PINException {

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION 1: The format must be correct
    validateFormat(buffer, offset, length);

    // PRE-CONDITION 2: The PIN rules must pass
    validateRules(buffer, offset, length);

    // PRE-CONDITION 3: The PIN history check must pass (this will update the history record)
    validateHistory(buffer, offset, length);

    //
    // EXECUTION
    // 

    // Process case-invariant values first (if applicable)
    processInvariantPin(buffer, offset, length);

    // We passed the history check, update and set our new state
    pin.update(buffer, offset, (byte) length);
    state = STATE_INITIALISED;
  }
}
