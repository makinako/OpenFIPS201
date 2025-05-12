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

import javacard.framework.PINException;
import org.globalplatform.CVM;
import org.globalplatform.GPSystem;

/** Provides an OwnerPIN proxy to the CVM class to allow uniform handling */
final class PIVCVMPIN implements PIVPIN {

  private final CVM cvm;

  /** Constructor */
  PIVCVMPIN() throws PINException {

    // Get our CVM reference
    cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);
  }

  @Override
  public byte getTriesRemaining() {
    return cvm.getTriesRemaining();
  }

  @Override
  public boolean check(byte[] pin, short offset, byte length)
      throws ArrayIndexOutOfBoundsException, NullPointerException {
    return (CVM.CVM_SUCCESS == cvm.verify(pin, offset, length, CVM.FORMAT_HEX));
  }

  @Override
  public boolean isValidated() {
    return cvm.isVerified();
  }

  @Override
  public void reset() {
    cvm.resetState();
  }

  @Override
  public void update(byte[] pin, short offset, byte length) throws PINException {
    cvm.update(pin, offset, length, CVM.FORMAT_HEX);
  }

  @Override
  public byte getTryLimit() {
    return (short) 0;
  }

  public void setTryLimit(byte limit) {
    // Do nothing
    PINException.throwIt(PINException.ILLEGAL_VALUE);
  }

  public boolean supportsSetTryLimit() {
    // GPRegistryEntry reg = GPSystem.getRegistryEntry(null);
    // return reg.isPrivileged(GPRegistryEntry.PRIVILEGE_CVM_MANAGEMENT);
    return false;
  }
}
