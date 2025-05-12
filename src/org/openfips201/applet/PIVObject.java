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

/** Provides common functionality for all PIV objects (data and security) */
abstract class PIVObject {

  //
  // Access Rule for Read/Usage (SP800-73-4 3.5)
  // NOTES:
  // - This is a control flag bitmap, so multiple access rules can be combined.
  // - NEVER and ALWAYS are special values, not considered part of the bitmap and
  //   cannot be combined with any other values.

  // The object may be read / key may be used under no circumstances
  static final byte ACCESS_MODE_NEVER = (byte) 0x00;

  // The object may be accessed only after PIN authentication
  static final byte ACCESS_MODE_PIN = (byte) 0x01;

  // The object may be accessed only IMMEDIATELY after PIN, OCC or KEY_HOLDER authentication
  static final byte ACCESS_MODE_IMMEDIATE = (byte) 0x02;

  // The object may be accessed after OCC authentication
  static final byte ACCESS_MODE_OCC = (byte) 0x04;

  // The object may be accessed ONLY over an established PIV Secure Messaging channel
  // NOTE: This is an independent criteria to any other access condition.
  static final byte ACCESS_MODE_SM = (byte) 0x40;
  
  // The object may be managed to by a user who has satisfied the access
  // conditions.
  // NOTES:
  // - For data objects, this is used by PUT DATA to permit writing
  // - For key objects, this permits GENERATE ASSYMMETRIC KEYPAIR only.
  static final byte ACCESS_MODE_USER_ADMIN = (byte) 0x80;

  // The object may be accessed ALWAYS
  static final byte ACCESS_MODE_ALWAYS = (byte) 0x3F; // Special value rather than a bitmap

  static final short HEADER_MODE_CONTACT = (short) 0;
  static final short HEADER_MODE_CONTACTLESS = (short) 1;

  // This can be overridden by derived classes
  static final short LENGTH_HEADER = (short) 2;

  // PERSISTENT - Linked list element
  PIVObject nextObject;

  // PERSISTENT - Object identifier
  protected int id;

  // PERSISTENT - Object header
  protected final byte[] header;

  /**
   * Constructs an instance of the base PIVObject object.
   *
   * @param id              The object identifier
   * @param modeContact     The access conditions for the contact interface.
   * @param modeContactless The access conditions for the contact interface.
   * @param adminKey        The access conditions for the contact interface.
   * @param extendedHeaders The number of additional headers to allocate (used by
   *                        derived classes)
   */
  PIVObject(int id, byte modeContact, byte modeContactless) {

    // A derived class can create this first with a larger size
    header = new byte[getHeaderLength()];

    this.id = id;

    header[HEADER_MODE_CONTACT] = modeContact;
    header[HEADER_MODE_CONTACTLESS] = modeContactless;

    // RULE 1: If userAdmin is set, either pin, pinAlways or occ must be set
    if ((modeContact & ACCESS_MODE_USER_ADMIN) == ACCESS_MODE_USER_ADMIN
        && (modeContact & ACCESS_MODE_PIN) != ACCESS_MODE_PIN
        && (modeContact & ACCESS_MODE_IMMEDIATE) != ACCESS_MODE_IMMEDIATE
        && (modeContact & ACCESS_MODE_OCC) != ACCESS_MODE_OCC) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if ((modeContactless & ACCESS_MODE_USER_ADMIN) == ACCESS_MODE_USER_ADMIN
        && (modeContactless & ACCESS_MODE_PIN) != ACCESS_MODE_PIN
        && (modeContactless & ACCESS_MODE_IMMEDIATE) != ACCESS_MODE_IMMEDIATE
        && (modeContactless & ACCESS_MODE_OCC) != ACCESS_MODE_OCC) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  protected short getHeaderLength() {
    return LENGTH_HEADER;
  }
  
  protected abstract short getHeader(TLVWriter writer);

  /*
   * Searches all PIVObject instances linked from this object until it matches one by id
   */
  PIVObject select(int id) {
    PIVObject current = this;

    while (current != null && current.id != id) {
      current = current.nextObject;
    }

    return current;
  }

  PIVObject last() {
    PIVObject current = this;

    while (current.nextObject != null) {
      current = current.nextObject;
    }

    return current;
  }

  /**
   * Returns the ACCESS MODE conditions for the contact interface
   *
   * @return The access mode for the contact interface
   */
  byte getModeContact() {
    return header[HEADER_MODE_CONTACT];
  }

  /**
   * Returns the ACCESS MODE conditions for the contactless interface
   *
   * @return The access mode for the contactless interface
   */
  byte getModeContactless() {
    return header[HEADER_MODE_CONTACTLESS];
  }

  /**
   * Clears all data and/or key values and marks the object as uninitialised.
   *
   * <p>
   * Note: If the card does not support ObjectDeletion, repeatedly calling this
   * method may exhaust NV RAM.
   */
  abstract void clear();

  /**
   * @return returns true if the object has been initialized
   */
  abstract boolean isInitialised();

  /**
   * Returns the administrative key used to manage this object
   * @return
   */
  abstract byte getAdminKey();
}