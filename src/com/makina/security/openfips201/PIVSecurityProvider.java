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

import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.RandomData;

@SuppressWarnings("unused")

/**
 * Provides all security and cryptographic services required by PIV, including the storage of PIN
 * and KEY objects, as well as cryptographic primitives.
 */
public final class PIVSecurityProvider {

  //
  // Persistent Objects
  //

  // If non-zero, the current communications interface is contactless
  private static final short FLAG_CONTACTLESS = (short) 0;
  // If non-zero, a valid GP Secure Channel authentication with CENC+CMAC is established
  private static final short FLAG_SECURE_CHANNEL = (short) 1;
  // If non-zero, a PIN verification occurred prior to the last GENERAL AUTHENTICATE command
  private static final short FLAG_PIN_ALWAYS = (short) 2;
  private static final short LENGTH_FLAGS = (short) 3;
  // PIN objects
  public final OwnerPIN cardPIN; // 80 - Card Application PIN
  public final OwnerPIN cardPUK; // 81 - PIN Unlocking Key (PUK)
  public final CVMPIN globalPIN; // 00 - Global PIN

  // Cryptographic Service Providers
  private final RandomData cspRNG;

  // Security Status Flags
  private final boolean[] securityFlags;
  // Key objects
  private PIVKeyObject firstKey;

  public PIVSecurityProvider() {

    // Create all CSP's, including the shared key instances
    cspRNG = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    PIVKeyObjectSYM.createProviders();
    PIVKeyObjectECC.createProviders();
    PIVKeyObjectRSA.createProviders();

    // Create our security flags
    securityFlags = JCSystem.makeTransientBooleanArray(LENGTH_FLAGS, JCSystem.CLEAR_ON_DESELECT);

    //
    // Create our PIN objects
    //

    // Mandatory
    cardPIN = new OwnerPIN(Config.PIN_RETRIES, Config.PIN_LENGTH_MAX);

    // Mandatory
    cardPUK = new OwnerPIN(Config.PUK_RETRIES, Config.PIN_LENGTH_MAX);

    // Optional - But we still have to create it because it can be enabled at runtime
    globalPIN = new CVMPIN(Config.PIN_RETRIES, Config.PIN_LENGTH_MAX);
  }

  public void resetSecurityStatus() {

    if (cardPIN.isValidated()) cardPIN.reset();
    if (cardPUK.isValidated()) cardPUK.reset();
    if (Config.FEATURE_PIN_GLOBAL_ENABLED && globalPIN.isValidated()) globalPIN.reset();

    PIVKeyObject key = firstKey;
    while (key != null) {
      key.resetSecurityStatus();
      key = (PIVKeyObject) key.nextObject;
    }
  }

  public boolean getPINAlways() {
    return (securityFlags[FLAG_PIN_ALWAYS] && (cardPIN.isValidated() || globalPIN.isValidated()));
  }

  public void setPINAlways(boolean value) {
    securityFlags[FLAG_PIN_ALWAYS] = value;
  }

  /**
   * Gets the current flag for whether the communications interface is contactless
   *
   * @return True if the current communications interface is contactless
   */
  public boolean getIsContactless() {
    return securityFlags[FLAG_CONTACTLESS];
  }

  /**
   * Sets the current flag for whether the communications interface is contactless
   *
   * @param value The new value to set
   */
  public void setIsContactless(boolean value) {
    securityFlags[FLAG_CONTACTLESS] = value;
  }

  /**
   * Gets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @return True if there is a current GlobalPlatform Secure Channel with CENC+CMAC
   */
  public boolean getIsSecureChannel() {
    return securityFlags[FLAG_SECURE_CHANNEL];
  }

  /**
   * Sets the current flag for the GlobalPlatform Secure Channel Status
   *
   * @param value The new value to set
   */
  public void setIsSecureChannel(boolean value) {
    securityFlags[FLAG_SECURE_CHANNEL] = value;
  }

  public PIVKeyObject selectKey(byte id, byte mechanism) {

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

  public boolean keyExists(byte id) {

    PIVKeyObject key = firstKey;

    // Traverse the linked list
    while (key != null) {
      if (key.match(id)) return true;
      key = (PIVKeyObject) key.nextObject;
    }

    return false;
  }

  /**
   * Adds a key to the internal key store
   *
   * @param id The key reference identifier
   * @param modeContact The access mode for the contact interface
   * @param modeContactless The access mode for the contactless interface
   * @param mechanism The cryptographic mechanism
   * @param role The key role / privileges control bitmap
   */
  public void createKey(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    // Create our new key
    PIVKeyObject key =
        PIVKeyObject.create(id, modeContact, modeContactless, mechanism, role, attributes);

    // Add it to our linked list
    // NOTE: If this is the first key added, just set our firstKey. Otherwise add it to the head 
    // to save a traversal (inspired by having no good answer to Steve Paik's question why we
    // add it to the end).
    if (firstKey == null) {
      firstKey = key;
    }
    else 
    {
      // Insert at the head of the list
      key.nextObject = firstKey;
      firstKey = key;	    
    }    
  }

  /**
   * Validates the current security conditions for performing card management commands
   *
   * @param requiresSecureChannel If true, a GlobalPlatform SCP session must be active
   * @return True if the access mode check passed
   */
  public boolean checkAccessModeAdmin(boolean requiresSecureChannel) {

    //
    // This check can pass by either the FLAG_SECURE_CHANNEL flag being set, or by finding
    // a key in the keystore that has the role attribute ROLE_ADMIN and is authenticated.
    //
    // If the requiresEncryption flag is set, then only FLAG_SECURE_CHANNEL is checked.
    //

    boolean valid = false;

    // Iterate through the key store for ROLE_ADMIN keys
    if (!requiresSecureChannel) {
      PIVKeyObject key = firstKey;
      while (key != null) {
        if (key.hasAttribute(PIVKeyObject.ATTR_ADMIN) && key.getSecurityStatus()) {
          valid = true;
          break;
        }
        key = (PIVKeyObject) key.nextObject;
      }
    }

    // Apply the GP SCP test
    // NOTE: If the FEATURE_RESTRICT_ADMIN_TO_CONTACT flag is set, it is not possible
    // 		 for FLAG_SECURE_CHANNEL to be set as the OpenFIPS201.process() checks
    //		 if it is permitted to execute GP Authentication over contactless.
    valid |= securityFlags[FLAG_SECURE_CHANNEL];

    // Now that we have performed a security check, clear the pinAlways flag
    securityFlags[FLAG_PIN_ALWAYS] = false;

    return valid;
  }

  /**
   * Validates the current security conditions for access to a given data or key object
   *
   * @param object The object to check permissions for
   * @return True of the access mode check passed
   */
  public boolean checkAccessModeObject(PIVObject object) {

    boolean valid = false;

    // Select the appropriate access mode to check
    byte mode =
        (securityFlags[FLAG_CONTACTLESS]) ? object.getModeContactless() : object.getModeContact();

    // Check for special ALWAYS condition, which ignores PIN_ALWAYS
    if (mode == PIVObject.ACCESS_MODE_ALWAYS) {
      valid = true;
    }
    else {
      // Check for PIN and GLOBAL PIN
      if ( (mode & PIVObject.ACCESS_MODE_PIN) == PIVObject.ACCESS_MODE_PIN
		   || (mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS) {
        // At least one PIN type must be both Enabled and Validated or we fail
        if (Config.FEATURE_PIN_CARD_ENABLED && cardPIN.isValidated())
        {
          valid = true;
        }
        if (Config.FEATURE_PIN_GLOBAL_ENABLED && globalPIN.isValidated()) {
          valid = true;
        }
      }

      // Check for PIN ALWAYS    
      if ((mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS
          && !securityFlags[FLAG_PIN_ALWAYS]) {
        valid = false;
      }

      // Now that we have performed a security check, clear the pinAlways flag
      securityFlags[FLAG_PIN_ALWAYS] = false;    
    }

    // Done
    return valid;
  }

  /**
   * Generates a number of random bytes using the SECURE_RANDOM generator
   *
   * @param buffer The buffer to write the random data to
   * @param offset The starting offset to write the random data
   * @param length The number of bytes to generate
   */
  public void generateRandom(byte[] buffer, short offset, short length) {
    cspRNG.generateData(buffer, offset, length);
  }

  /**
   * Performs a comprehensive erase of the target buffer
   *
   * @param buffer The buffer to clear
   * @param offset The starting offset of the buffer
   * @param length The length within the buffer to clear
   */
  public static void zeroise(byte[] buffer, short offset, short length) {

    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0xFF);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
  }
}
