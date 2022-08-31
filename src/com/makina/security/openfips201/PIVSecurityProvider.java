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
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

/**
 * Provides all security and cryptographic services required by PIV, including the storage of PIN
 * and KEY objects, as well as cryptographic primitives.
 */
final class PIVSecurityProvider {

  //
  // Constants - Security Flags
  //

  // If non-zero, the current communications interface is contactless
  private static final short STATE_IS_CONTACTLESS = (short) 0;

  // If non-zero, a valid GP Secure Channel authentication with CENC+CMAC is established
  private static final short STATE_IS_SECURE_CHANNEL = (short) 1;

  // If non-zero, a PIN verification occurred prior to the last GENERAL AUTHENTICATE command
  private static final short STATE_PIN_ALWAYS = (short) 2;

  // If non-zero, indicates the last key that was successfully authenticated
  private static final short STATE_AUTH_KEY = (short) 3;

  private static final short LENGTH_TRANSIENT_STATE = (short) 4;

  //
  // Constants - Security Counters
  //
  private static final short STATE_HISTORY_NEXT = (short) 0;
  private static final short LENGTH_PERSISTENT_STATE = (short) 1;

  //
  // Persistent Objects
  //

  // PERSISTENT - PIN objects
  private final PIVPIN cardPIN; // 80 - Card Application PIN
  private final PIVPIN cardPUK; // 81 - PIN Unlocking Key (PUK)
  private final PIVPIN globalPIN; // 00 - Global PIN
  private final OwnerPIN[] pinHistory;

  // PERSISTENT - Counters related to security operations
  private final byte[] persistentState;

  // PERSISTENT - Key objects (linked list)
  private PIVKeyObject firstKey;

  //
  // Transient Objects
  //

  // TRANSIENT - Security Status Flags
  private final byte[] transientState;

  private static final byte FLAG_FALSE = (byte) 0;
  private static final byte FLAG_TRUE = (byte) 0xFF;

  PIVSecurityProvider() {

    // Initialise our PIV crypto provider
    PIVCrypto.init();

    // Create our internal state
    transientState =
        JCSystem.makeTransientByteArray(LENGTH_TRANSIENT_STATE, JCSystem.CLEAR_ON_DESELECT);
    persistentState = new byte[LENGTH_PERSISTENT_STATE];

    //
    // Create our PIN objects
    //

    // TODO: Change this to be made when the applet transitions to the PERSONALISED state and state
    // the limitation that it can only be set once. This is because OwnerPIN won't let you change it

    // Mandatory
    cardPIN = new PIVOwnerPIN(Config.LIMIT_PIN_MAX_RETRIES, Config.LIMIT_PIN_MAX_LENGTH);

    // Mandatory
    cardPUK = new PIVOwnerPIN(Config.LIMIT_PUK_MAX_RETRIES, Config.LIMIT_PUK_MAX_LENGTH);

    // Optional - But we still have to create it because it can be enabled at runtime
    globalPIN = new PIVCVMPIN();

    // Supplemental - PIN History
    pinHistory = new OwnerPIN[Config.LIMIT_PIN_HISTORY];
    for (short i = 0; i < Config.LIMIT_PIN_HISTORY; i++) {
      // We don't need to make use of retry features for history PIN values
      // as we will reset them every time.
      pinHistory[i] = new OwnerPIN((byte) 1, Config.LIMIT_PIN_MAX_LENGTH);
      // TODO: Probably need to initialise these even though it isn't a security risk
    }
  }

  void clearVerification() {
    // Reset all PINs
    if (cardPIN.isValidated()) cardPIN.reset();
    if (cardPUK.isValidated()) cardPUK.reset();
    if (globalPIN.isValidated()) globalPIN.reset();
  }

  void setAuthenticatedKey(byte key) {
    transientState[STATE_AUTH_KEY] = key;
  }

  void clearAuthenticatedKey() {
    // Reset any authenticated keys
    // NOTE: We do NOT reset the secure channel, which is controlled from the applet
    transientState[STATE_AUTH_KEY] = (byte) 0;
  }

  boolean getIsPINAlways() {
    return (transientState[STATE_PIN_ALWAYS] == FLAG_TRUE
        && (cardPIN.isValidated() || globalPIN.isValidated()));
  }

  void setPINAlways(boolean value) {
    // TODO: Get rid of this and make PIN verification abstracted
    transientState[STATE_PIN_ALWAYS] = value ? FLAG_TRUE : FLAG_FALSE;
  }

  boolean getIsPINVerified() {
    return (cardPIN.isValidated() || globalPIN.isValidated());
  }

  /**
   * Gets the current flag for whether the communications interface is contactless
   *
   * @return True if the current communications interface is contactless
   */
  boolean getIsContactless() {
    return (transientState[STATE_IS_CONTACTLESS] == FLAG_TRUE);
  }

  /**
   * Sets the current flag for whether the communications interface is contactless
   *
   * @param value The new value to set
   */
  void setIsContactless(boolean value) {
    transientState[STATE_IS_CONTACTLESS] = value ? FLAG_TRUE : FLAG_FALSE;
  }

  /**
   * Gets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @return True if there is a current GlobalPlatform Secure Channel with CENC+CMAC
   */
  boolean getIsSecureChannel() {
    return (transientState[STATE_IS_SECURE_CHANNEL] == FLAG_TRUE);
  }

  /**
   * Sets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @param value The new value to set
   */
  void setIsSecureChannel(boolean value) {
    transientState[STATE_IS_SECURE_CHANNEL] = value ? FLAG_TRUE : FLAG_FALSE;
  }

  PIVKeyObject selectKey(byte id, byte mechanism) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    PIVKeyObject key = firstKey;

    // Traverse the linked list
    while (key != null) {
      if (key.match(id, mechanism)) return key;
      key = (PIVKeyObject) key.nextObject;
    }

    return null;
  }

  boolean keyExists(byte id) {

    PIVObject key = firstKey;

    // Traverse the linked list
    while (key != null) {
      if (key.match(id)) return true;
      key = key.nextObject;
    }

    return false;
  }

  /**
   * Adds a key to the internal key store
   *
   * @param id The key reference identifier
   * @param modeContact The access mode for the contact interface
   * @param modeContactless The access mode for the contactless interface
   * @param adminKey The administrative key for this key object
   * @param mechanism The cryptographic mechanism
   * @param role The key role / privileges control bitmap
   * @param attributes The optional key attributes
   */
  void createKey(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    // Create our new key
    PIVKeyObject key =
        PIVKeyObject.create(
            id, modeContact, modeContactless, adminKey, mechanism, role, attributes);

    // Add it to our linked list
    // NOTE: If this is the first key added, just set our firstKey. Otherwise add it to the head
    // to save a traversal (inspired by having no good answer to Steve Paik's question why we
    // add it to the end).
    if (firstKey == null) {
      firstKey = key;
    } else {
      // Insert at the head of the list
      key.nextObject = firstKey;
      firstKey = key;
    }
  }

  /**
   * Validates the current security conditions for administering the specified object.
   *
   * @param object The object to check permissions for
   * @return True of the access mode check passed
   */
  boolean checkAccessModeAdmin(PIVObject object) {

    //
    // This check can pass by any of the following conditions being true:
    // 1) The STATE_IS_SECURE_CHANNEL flag is set
    // 2) The object admin key is the last successfully authenticated key
    // 3) The object has the USER_ADMIN flag set and passes normal read access conditions, with
    //    the exception of objects that can ALWAYS be read.
    //

    boolean result = false;

    byte mode;
    if (getIsContactless()) {
      mode = object.getModeContactless();
    } else {
      mode = object.getModeContact();
    }

    //
    // ACCESS CONDITION 1 - Secure Channel (God Mode)
    //
    if (getIsSecureChannel()) {
      result = true;
    }

    //
    // ACCESS CONDITION 2 - Administrative Key
    //
    if (object.getAdminKey() == transientState[STATE_AUTH_KEY]) {
      result = true;
    }

    //
    // ACCESS CONDITION 3 - User Administration Privilege
    //
    if ((mode != PIVObject.ACCESS_MODE_ALWAYS)
        && ((mode & PIVObject.ACCESS_MODE_USER_ADMIN) == PIVObject.ACCESS_MODE_USER_ADMIN)
        && checkAccessModeObject(object)) {
      result = true;
    }

    // Now that we have performed a security check, clear the pinAlways flag
    // NOTE: This incidentally always runs with access condition 3 above.
    setPINAlways(false);

    // Done
    return result;
  }

  /**
   * Validates the current security conditions for access to a given data or key object
   *
   * @param object The object to check permissions for
   * @return True of the access mode check passed
   */
  boolean checkAccessModeObject(PIVObject object) {

    boolean valid = false;

    // Select the appropriate access mode to check
    byte mode;
    if (transientState[STATE_IS_CONTACTLESS] == FLAG_TRUE) {
      mode = object.getModeContactless();
    } else {
      mode = object.getModeContact();
    }

    // Check for special ALWAYS condition, which ignores PIN_ALWAYS
    if (mode == PIVObject.ACCESS_MODE_ALWAYS) {
      valid = true;
    } else {
      // Check for PIN and GLOBAL PIN
      if ((mode & PIVObject.ACCESS_MODE_PIN) == PIVObject.ACCESS_MODE_PIN
          || (mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS) {
        // At least one PIN type must be both Enabled and Validated or we fail
        // NOTE: We don't check if they are enabled here, because if they weren't they could
        // never be valid.
        if (cardPIN.isValidated() || globalPIN.isValidated()) {
          valid = true;
        }
      }

      // Check for PIN_ALWAYS
      if (((mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS)
          && transientState[STATE_PIN_ALWAYS] != FLAG_TRUE) {
        valid = false;
      }
    }

    // Now that we have performed a security check, clear the pinAlways flag
    transientState[STATE_PIN_ALWAYS] = FLAG_FALSE;

    // Done
    return valid;
  }

  PIVPIN getPIN(byte id) {

    switch (id) {
      case PIV.ID_CVM_LOCAL_PIN:
        return cardPIN;

      case PIV.ID_CVM_GLOBAL_PIN:
        return globalPIN;

      case PIV.ID_CVM_PUK:
        return cardPUK;

      default:
        return null; // Keep compiler happy
    }
  }

  void updatePIN(byte id, byte[] buffer, short offset, byte length, byte historyCount) {

    PIVPIN pin;

    switch (id) {
      case PIV.ID_CVM_LOCAL_PIN:
        pin = cardPIN;
        break;

      case PIV.ID_CVM_GLOBAL_PIN:
        pin = globalPIN;
        break;

      case PIV.ID_CVM_PUK:
        // Update the PUK, no history matching required
        cardPUK.update(buffer, offset, length);
        return;

      default:
        ISOException.throwIt(PIV.SW_REFERENCE_NOT_FOUND);
        return; // Keep compiler happy
    }

    // Optionally verify the PIN history
    // NOTE: Any elements beyond the historyCheck count will not be used at all, so we ignore
    // their values
    boolean matched = false;

    // Interate through our history list (which may be zero)
    for (byte i = 0; i < historyCount; i++) {
      OwnerPIN p = pinHistory[i];
      if (p != null) {
        if (p.getTriesRemaining() == 0) p.resetAndUnblock();
        if (p.check(buffer, offset, length)) {
          // We matched, no further checks required
          matched = true;
          break;
        }
      }
    }

    // If we got a match, the PIN check fails and we will not update
    if (matched) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return; // Keep compiler happy
    }

    // Update the PIN
    pin.update(buffer, offset, length);

    // Update the PIN History if enabled
    if (historyCount > 0) {
      // Move/Roll to the next position we will write to
      byte next = persistentState[STATE_HISTORY_NEXT];
      pinHistory[next].update(buffer, offset, length);
      next = (byte) ((byte) (next + (byte) 1) % historyCount);
      persistentState[STATE_HISTORY_NEXT] = next;
    }
  }

  /**
   * Performs a comprehensive erase of the target buffer
   *
   * @param buffer The buffer to clear
   * @param offset The starting offset of the buffer
   * @param length The length within the buffer to clear
   */
  static void zeroise(byte[] buffer, short offset, short length) {

    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0xFF);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
  }
}
