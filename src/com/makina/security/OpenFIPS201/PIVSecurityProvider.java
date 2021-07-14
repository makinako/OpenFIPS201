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

package com.makina.security.OpenFIPS201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

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
  private final Cipher cspAES;
  private final Cipher cspTDEA;
  private final Cipher cspRSASigner;
  private final KeyAgreement cspECDH;
  private final RandomData cspRNG;
  private final Signature cspSHA1Signer;
  private final Signature cspSHA256Signer;
  private final Signature cspSHA384Signer;
  private final Signature cspSHA512Signer;

  // Security Status Flags
  private final boolean[] securityFlags;
  // Key objects
  private PIVKeyObject firstKey;

  public PIVSecurityProvider() {

    // Create our CSPs
    cspAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    cspTDEA = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
    cspECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    cspRSASigner = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    cspRNG = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    cspSHA1Signer = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    cspSHA256Signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    cspSHA384Signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
    cspSHA512Signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);

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
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {

    // First, map the default mechanism code to TDEA 3KEY
    if (mechanism == PIV.ID_ALG_DEFAULT) {
      mechanism = PIV.ID_ALG_TDEA_3KEY;
    }

    // Create our new key
    PIVKeyObject key = PIVKeyObject.create(id, modeContact, modeContactless, mechanism, role);

    // Check if this is the first key added
    if (firstKey == null) {
      firstKey = key;
      return;
    }

    // Find the last key
    PIVObject last = firstKey;
    while (last.nextObject != null) {
      last = last.nextObject;
    }

    // Assign the next
    last.nextObject = key;
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
      while (key != null && !valid) {
        if (key.hasRole(PIVKeyObject.ROLE_ADMIN) && key.getSecurityStatus()) {
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

    boolean valid;

    // Select the appropriate access mode to check
    byte mode =
        securityFlags[FLAG_CONTACTLESS] ? object.getModeContactless() : object.getModeContact();

    if (mode == PIVObject.ACCESS_MODE_NEVER) {
      valid = false;
    } else if (mode == PIVObject.ACCESS_MODE_ALWAYS) {
      valid = true;
    } else {
      // Assume true, then if any required permission is not met, we fail
      valid = true;

      // Check for PIN and GLOBAL PIN
      if ((mode & PIVObject.ACCESS_MODE_PIN) == PIVObject.ACCESS_MODE_PIN) {

        // If both FEATURE_PIN_CARD_ENABLED and FEATURE_PIN_GLOBAL_VERIFY are false, automatically
        // fail
        if (!Config.FEATURE_PIN_CARD_ENABLED && !Config.FEATURE_PIN_GLOBAL_ENABLED) {
          valid = false;
        }

        // Now that we know at least one of them must be enabled, either being enabled AND valid
        // will do
        else if (!(Config.FEATURE_PIN_CARD_ENABLED && cardPIN.isValidated())
            || (Config.FEATURE_PIN_GLOBAL_ENABLED && globalPIN.isValidated())) {
          valid = false;
        }
      }

      // Check for PIN ALWAYS
      if (((mode & PIVObject.ACCESS_MODE_PIN_ALWAYS) == PIVObject.ACCESS_MODE_PIN_ALWAYS)
          && !securityFlags[FLAG_PIN_ALWAYS]) {
        valid = false;
      }
    }

    // Now that we have performed a security check, clear the pinAlways flag
    securityFlags[FLAG_PIN_ALWAYS] = false;

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
    if (Config.FEATURE_PIV_TEST_VECTORS) {
      Util.arrayCopyNonAtomic(Config.TEST_VECTOR_RANDOM, (short) 0, buffer, offset, length);
    } else {
      cspRNG.generateData(buffer, offset, length);
    }
  }

  /**
   * Performs a cryptographic encipherment operation using the supplied key
   *
   * @param key The key to use for encipherment
   * @param inBuffer The buffer containing the plaintext
   * @param inOffset The offset for inBuffer
   * @param inLength The number of plaintext bytes to encipher
   * @param outBuffer The buffer to write the ciphertext to
   * @param outOffset The offset for outBuffer
   * @return The length of the ciphertext bytes written
   */
  public short encrypt(
      PIVKeyObject key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    if (!(key instanceof PIVKeyObjectSYM)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
    Cipher cipher = null;

    switch (key.getMechanism()) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        cipher = cspTDEA;
        break;

      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        cipher = cspAES;
        break;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    return ((PIVKeyObjectSYM) key)
        .encrypt(cipher, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  public short sign(
      PIVKeyObject key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    if (!key.isAsymmetric()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    Object signer = null;
    if (key instanceof PIVKeyObjectRSA) {
      signer = cspRSASigner;
    } else {
      switch (inLength) {
        case MessageDigest.LENGTH_SHA:
          signer = cspSHA1Signer;
          break;
        case MessageDigest.LENGTH_SHA_256:
          signer = cspSHA256Signer;
          break;
        case MessageDigest.LENGTH_SHA_384:
          signer = cspSHA384Signer;
          break;
        case MessageDigest.LENGTH_SHA_512:
          signer = cspSHA512Signer;
          break;
        default:
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      }
    }
    return ((PIVKeyObjectPKI) key).sign(signer, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  public short keyAgreement(
      PIVKeyObject key,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    if (!key.isAsymmetric()) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    return ((PIVKeyObjectPKI) key)
        .keyAgreement(cspECDH, inBuffer, inOffset, inLength, outBuffer, outOffset);
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
