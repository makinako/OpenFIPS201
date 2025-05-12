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
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

class Operator {

  //
  // Constants - Authentication States
  //

  // The operator has not authenticated to any roles.
  static final byte ROLE_NONE = (byte) 0x00;

  // The operator is authenticated as a 'User'.
  static final byte ROLE_USER = (byte) 0x01;

  // The operator is authenticated as a 'Security Officer'.
  static final byte ROLE_SECURITY_OFFICER = (byte) 0x02;

  // The operator is authenticated as a 'Key Holder'.
  static final byte ROLE_KEY_HOLDER = (byte) 0x04;

  // The operator is authenticated as an 'Administrator'.
  static final byte ROLE_ADMIN = (byte) 0x40;

  // Indicates the current applet authentication state
  private static final short OFFSET_ROLES = (short) 0;

  // If non-zero, indicates the last KEY reference that was successfully
  // authenticated
  private static final short OFFSET_ID = (short) 1;

  // If non-zero, a valid authentication occurred prior to the last permissions check
  private static final short OFFSET_IMMEDIATE = (short) 2;

  // Integrity check digest for operator state
  private static final short LENGTH_NONCE = (short) 8;
  private static final short OFFSET_NONCE = (short) 3;

  private static final short LENGTH_CMAC = (short) 16;
  private static final short OFFSET_CMAC = (short) (OFFSET_NONCE + LENGTH_NONCE);
  private static final short LENGTH_STATE = (short) (3 + LENGTH_NONCE + LENGTH_CMAC);
  private static final short LENGTH_CMAC_INPUT = (short) (3 + LENGTH_NONCE);

  // PERSISTENT - Integrity CMAC Key
  private final AESKey integrityKey;

  // TRANSIENT - Holds operator authentication
  private final byte[] state;

  Operator() {
    // Operator state needs to be CLEAR_ON_RESET because of the 'Applet reselection' rules, so 
    // we leave it to the Applet.deselect() method to decide if operator state should be cleared.
    state = JCSystem.makeTransientByteArray(LENGTH_STATE, JCSystem.CLEAR_ON_RESET);

    // Generate the AES integrity key
    integrityKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

    // Temporarily use the operator CMAC space to generate a random integrity key value
    Platform.Cryptography.generateRandom(state, OFFSET_CMAC, (short) (integrityKey.getSize() / 8));
    integrityKey.setKey(state, OFFSET_CMAC);
    reset(); // This will clear the internal state and reset the CAMC    
  }

  void performIntegrityCheck() {
    // If the role is ROLE_NONE, we skip the integrity check as the default state on RESET will
    // be all zeroes and since no sensitive role is being claimed, there is no danger.
    if (state[OFFSET_ROLES] == ROLE_NONE) {
      return;
    }

    // If the check fails, explicitly reset all operator state and update the CMAC.
    if (!Platform.Cryptography.verifyCMAC(integrityKey, state, Constants.ZERO_SHORT, LENGTH_CMAC_INPUT, state,
        OFFSET_CMAC, LENGTH_CMAC)) {
      reset();
      ISOException.throwIt(Constants.SW_OPERATOR_CHECK_FAILURE);
    }
   }

  private void updateIntegrityCheck() {
    // Update the nonce
    Platform.Cryptography.generateRandom(state, OFFSET_NONCE, LENGTH_NONCE);

    // Update the CMAC across all state data
    Platform.Cryptography.computeCMAC(integrityKey, state, Constants.ZERO_SHORT, LENGTH_CMAC_INPUT, state, OFFSET_CMAC);
  }

  /**
   * Clears any existing operator authentication status and reverts to the public role.
   */
  void reset() {
    Platform.zeroise(state, Constants.ZERO_SHORT, LENGTH_STATE);
    updateIntegrityCheck();
  }

  void clearRole(byte role) {

    // We must clear one and only one of the valid roles, anything else may be a bug or tamper evidence.
    if (role != ROLE_USER && role != ROLE_KEY_HOLDER && role != ROLE_SECURITY_OFFICER && role != ROLE_ADMIN) {
      reset();
      ISOException.throwIt(Constants.SW_OPERATOR_CHECK_FAILURE);
    }

    // Clear the requested role and the IMMEDIATE flag
    state[OFFSET_ROLES] &= ~role;
    state[OFFSET_IMMEDIATE] = Constants.FALSE_BYTE;

    // Clear the identity for KEY_HOLDER role
    if (role == ROLE_KEY_HOLDER) {
      state[OFFSET_ID] = Constants.ZERO_BYTE;
    }

    updateIntegrityCheck();
  }

  /**
   * Sets the operator to a given role, with no specific bound identity
   * 
   * @param role The role to set.
   */
  void setRole(byte role) {
    setRoleAndId(role, Constants.ZERO_BYTE);
  }

  /**
   * Sets the operator to a given role, with a specific identity. NOTE: Identity is used to refine
   * access control checks, for example: - For the 'User' role, the identity specifies which user
   * verification method was used. - For the 'Key Holder' role, the identity specifies which keys
   * was used.
   * 
   * @param role The role to set.
   */
  void setRoleAndId(byte role, byte id) {

    // We must set one and only one of the valid roles, anything else may be a bug or tamper evidence.
    if (role != ROLE_USER && role != ROLE_KEY_HOLDER && role != ROLE_SECURITY_OFFICER && role != ROLE_ADMIN) {
      reset();
      ISOException.throwIt(Constants.SW_OPERATOR_CHECK_FAILURE);
    }

    state[OFFSET_ROLES] |= role;
    if (id != 0) {
      state[OFFSET_ID] = id;      
    }

    // If the user is authenticated, set the PIN Always flag
    if (role == ROLE_USER || role == ROLE_KEY_HOLDER) {
      state[OFFSET_IMMEDIATE] = Constants.TRUE_BYTE;
    }

    updateIntegrityCheck();
  }

  boolean hasRole(byte role) {
    return (state[OFFSET_ROLES] & role) == role;
  }

  byte getId() {
    return state[OFFSET_ID];
  }

  byte getRoles() {
    return state[OFFSET_ROLES];
  }

  /**
   * Returns and then optionall clears the 'IMMEDIATE' flag. 
   * @return
   */
  boolean getImmediateFlag(boolean reset) {
    boolean result = state[OFFSET_IMMEDIATE] == Constants.TRUE_BYTE;
    if (reset) {
      state[OFFSET_IMMEDIATE] = Constants.FALSE_BYTE;
      updateIntegrityCheck();
    }
    return result;
  }
}
