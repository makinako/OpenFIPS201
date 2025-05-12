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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.PINException;
import javacard.framework.Util;

import org.globalplatform.CVM;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;

final class PIVVerifierCVMPIN extends PIVVerifierPIN {

  // PERSISTENT - The CVM reference
  private final CVM cvm;

  PIVVerifierCVMPIN(int id, byte modeContact, byte modeContactless, byte minLength,
      byte maxLength, byte retriesContact, byte retriesContactless, byte charset, byte ruleHistory,
      byte ruleSequence, byte ruleRepetition, byte restrictUpdate) {
    super(id, modeContact, modeContactless, minLength, maxLength, retriesContact,
        retriesContactless, charset, ruleHistory, ruleSequence, ruleRepetition, restrictUpdate);
    
    
    // Get our CVM reference
    cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);

    // The CVM may have had a value initialised prior to the applet install, so we check here
    state = (cvm.isActive() ? STATE_INITIALISED : STATE_UNINITIALISED);

    // Update our retry counter if we can
    if (canManage() && retriesContact > 0) {
      cvm.setTryLimit(retriesContact);
      
    }
  }
  
  private boolean canManage() {
    GPRegistryEntry registry = GPSystem.getRegistryEntry(null);
    return registry.isPrivileged(GPRegistryEntry.PRIVILEGE_CVM_MANAGEMENT);
  }

  @Override
  byte getContactTriesRemaining() {
    return cvm.getTriesRemaining();
  }

  @Override
  byte getContactlessTriesRemaining() {
    return cvm.getTriesRemaining();
  }

  @Override
  boolean check(byte[] buffer, short offset, short length)
      throws ArrayIndexOutOfBoundsException, NullPointerException {

    //
    // PRE-CONDITIONS
    //
    
    // PRE-CONDITION: The PIN must be initialised with a value
    if (!isInitialised()) {
      ISOException.throwIt(Constants.SW_REFERENCE_NOT_FOUND);
    }

    // PRE-CONDITION: - The PIN must not exceed the hard limits if authenticating
    if (length > PIVVerifierPIN.LIMIT_MAX_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    // PRE-CONDITION 1: The format must be correct
    validateFormat(buffer, offset, length);
    
    
    // NOTE: Any other invalid formatting will result in decrementing the pin
    // counter, which improves resistance to number space deduction.

    //
    // EXECUTION
    //
        
    // Process case-invariant values first (if applicable)
    processInvariantPin(buffer, offset, length);
    
    // Because we don't use the APDU as a general buffer now, we temporarily
    // use it here as the PIN buffer and zeroise immediately after.
    byte[] globalBuffer = APDU.getCurrentAPDUBuffer();
    try {
      Util.arrayCopyNonAtomic(buffer, offset, globalBuffer, ISO7816.OFFSET_CDATA, length);
      return (CVM.CVM_SUCCESS == cvm.verify(globalBuffer, ISO7816.OFFSET_CDATA, (byte)length, CVM.FORMAT_HEX));
    } finally {
      // Always zeroise this explicitly regardless of the outcome
      Platform.zeroise(globalBuffer, ISO7816.OFFSET_CDATA, length);
    }

  }

  @Override
  boolean isValidated() {
    return cvm.isVerified();
  }

  @Override
  void reset() {
    cvm.resetState();
  }

  @Override
  byte getTryLimit() {
    // NOTE: The CVM doesn't provide a getTryLimit() method for us, so we have to use the value
    // given during creation. If the CVM Management privilege wasn't given to this applet when
    // it is installed, this may end up returning the wrong value unless the issuer chose the 
    // same max retries value configured at the Card OS level.
    return header[HEADER_RETRIES_CONTACT];
  }

  @Override
  void update(byte[] buffer, short offset, short length) throws PINException {
    
    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: We must have management permission
    if (!canManage()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }
    
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
    
    // We use the APDU buffer here as it is an easily available global buffer
    // We deliberately avoid the start of the APDU in case the header is used in
    // response processing.
    byte[] globalBuffer = APDU.getCurrentAPDUBuffer();
    try {
      Util.arrayCopyNonAtomic(buffer, offset, globalBuffer, ISO7816.OFFSET_CDATA, length);
      if (!cvm.update(globalBuffer, ISO7816.OFFSET_CDATA, (byte) length, CVM.FORMAT_HEX)) {
        // The update failed because it was rejected.
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
      state = STATE_INITIALISED;
    } finally {
      // Always zeroise this explicitly regardless of the outcome
      Platform.zeroise(globalBuffer, ISO7816.OFFSET_CDATA, length);
    }
  }
}