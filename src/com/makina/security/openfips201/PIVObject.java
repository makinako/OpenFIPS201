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

/** Provides common functionality for all PIV objects (data and security) */
abstract class PIVObject {

  //
  // Access Rule for Read/Usage (SP800-73-4 3.5)
  // NOTES:
  // - This is a control flag bitmap, so multiple access rules can be combined.
  // - NEVER and ALWAYS are special values, not considered part of the bitmap and cannot be
  //   combined with any other values.

  // The object may be read / key may be used under no circumstances
  static final byte ACCESS_MODE_NEVER = (byte) 0x00;

  // The object may be accessed only after PIN authentication
  static final byte ACCESS_MODE_PIN = (byte) 0x01;

  // The object may be accessed only IMMEDIATELY after PIN authentication
  static final byte ACCESS_MODE_PIN_ALWAYS = (byte) 0x02;

  // The object may be accessed after OCC authentication
  static final byte ACCESS_MODE_OCC = (byte) 0x04;

  // The object may be managed to by a user who has satisfied the access conditions
  // NOTES:
  // - For data objects, this is used by PUT DATA to permit writing
  // - For key objects, this permits GENERATE ASSYMMETRIC KEYPAIR only.
  static final byte ACCESS_MODE_USER_ADMIN = (byte) 0x10;

  // The object may be accessed ALWAYS
  static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F; // Special value rather than a bitmap

  // The default administrative key reference
  static final byte DEFAULT_ADMIN_KEY = (byte) 0x9B;

  protected static final short HEADER_ID = (short) 0;
  protected static final short HEADER_MODE_CONTACT = (short) 1;
  protected static final short HEADER_MODE_CONTACTLESS = (short) 2;
  protected static final short HEADER_ADMIN_KEY = (short) 3;

  // We allocate some spare header space for derived attributes
  // TODO: Could improve this header creation by defining length in derived classes.
  protected static final short LENGTH_HEADER = (short) 8;

  // Linked list element
  // TODO: This needs to be abstracted out of the public eye
  PIVObject nextObject;
  protected final byte[] header;

  /**
   * Constructs an instance of the base PIVObject object.
   *
   * @param id The object identifier
   * @param modeContact The access conditions for the contact interface.
   * @param modeContactless The access conditions for the contact interface.
   * @param adminKey The access conditions for the contact interface.
   * @param extendedHeaders The number of additional headers to allocate (used by derived classes)
   */
  protected PIVObject(
      byte id, byte modeContact, byte modeContactless, byte adminKey, short extendedHeaders) {

    header = new byte[(short) (LENGTH_HEADER + extendedHeaders)];

    // If the administrative key is not specified, use the default (9B) key.
    if (adminKey == (byte) 0) {
      adminKey = PIVObject.DEFAULT_ADMIN_KEY;
    }

    header[HEADER_ID] = id;
    header[HEADER_MODE_CONTACT] = modeContact;
    header[HEADER_MODE_CONTACTLESS] = modeContactless;
    header[HEADER_ADMIN_KEY] = adminKey;
  }

  /**
   * Compares the requested identifier value to the current object's id
   *
   * @param id The id to search for
   * @return True if the object matches
   */
  boolean match(byte id) {
    return (header[HEADER_ID] == id);
  }

  /**
   * Returns the current object's identifier value
   *
   * @return The object identifier
   */
  byte getId() {
    return header[HEADER_ID];
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

  byte getAdminKey() {
    return header[HEADER_ADMIN_KEY];
  }

  /** Requests object deletion if supported by the card. */
  protected void runGc() {
    // Note that this will only execute on the next call the Applet.process()
    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }
  }

  /**
   * Clears all data and/or key values and marks the object as uninitialised.
   *
   * <p>Note: If the card does not support ObjectDeletion, repeatedly calling this method may
   * exhaust NV RAM.
   */
  abstract void clear();

  /**
   * @return returns true if the object has been initialized
   */
  abstract boolean isInitialised();
}
