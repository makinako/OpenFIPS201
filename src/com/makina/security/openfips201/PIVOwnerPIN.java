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

import javacard.framework.OwnerPIN;
import javacard.framework.PINException;

/*
 * Provides an application-specific OwnerPIN implementation.
 * <p>
 * This implementation internally uses an OwnerPIN for its implementation,
 * but it specifically permits the definition of a 'soft' retry limit, which
 * allows the application to define a retry limit which is <b>less</b> than
 * the initial hard limit imposed by the OwnerPIN instance.
 * <p>
 * The rationale for this is that JCRE 3.0.4 does not support updating the
 * try limit value. From a security perspective, storing the soft try limit
 * in a variable in this class means that this limit is less protected than
 * one stored in OwnerPIN. The exposure for this threat is only limited to the
 * hard retry limit value however.
 */
final class PIVOwnerPIN implements PIVPIN {

  /*
   * Defines the highest possible try limit, which is derived
   * from the fact that the SW12 value for an incorrect PIN only
   * permits the remaining attempts to be stored in a nibble.
   */
  public static final byte HARD_PIN_TRY_LIMIT = (byte) 15;

  private final OwnerPIN myPIN;
  private byte mySoftTryLimit;

  /**
   * Constructor
   *
   * @param tryLimit The number of incorrect attempts before blocking
   * @param maxPINSize The maximum length of the PIN
   */
  PIVOwnerPIN(byte tryLimit, byte maxPINSize) throws PINException {
    myPIN = new OwnerPIN(tryLimit, maxPINSize);

    // Initialise our soft try limit to the initial hard limit
    mySoftTryLimit = tryLimit;
  }

  @Override
  public byte getTriesRemaining() {
    byte retries = myPIN.getTriesRemaining();
    byte delta = (byte) (HARD_PIN_TRY_LIMIT - mySoftTryLimit);

    // NOTE:
    // - It should never be the case that retries gets under the delta value, because if it has
    //   then the PIN was permitted to be checked more than the soft limit. This provides a basic
    //   sanity check to ensure the PIN blocks regardless.
    if (retries < delta) {
      retries = 0;
    } else {
      retries -= delta;
    }
    return retries;
  }

  @Override
  public boolean check(byte[] pin, short offset, byte length)
      throws ArrayIndexOutOfBoundsException, NullPointerException {

    // Manually check the remaining retries here
    if (getTriesRemaining() <= 0) {
      PINException.throwIt(PINException.ILLEGAL_VALUE);
      return false; // Keep compiler happy
    }

    return myPIN.check(pin, offset, length);
  }

  @Override
  public boolean isValidated() {
    return myPIN.isValidated();
  }

  @Override
  public void reset() {
    myPIN.reset();
  }

  @Override
  public void update(byte[] pin, short offset, byte length) throws PINException {
    myPIN.update(pin, offset, length);
  }

  @Override
  public byte getTryLimit() {
    return mySoftTryLimit;
  }

  public void setTryLimit(byte limit) {
    if (limit < 0 || limit > HARD_PIN_TRY_LIMIT) {
      PINException.throwIt(PINException.ILLEGAL_VALUE);
    } else {
      mySoftTryLimit = limit;
    }
  }

  public boolean supportsSetTryLimit() {
    return true;
  }
}
