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

import javacard.framework.JCSystem;

/** Provides common functionality for all PIV objects (data and security) */
public abstract class PIVObject {

  //
  // Access Rule for Read/Usage (SP800-73-4 3.5)
  // NOTES:
  // - This is a control flag bitmap, so multiple access rules can be combined.
  // - NEVER and ALWAYS are special values, not considered part of the bitmap
  // - The VCI and OCC options are out-of-scope in this implementation.

  // The object may be read / key may be used under no circumstances
  public static final byte ACCESS_MODE_NEVER = (byte) 0x00;

  // The object may be accessed only after PIN authentication
  public static final byte ACCESS_MODE_PIN = (byte) 0x01;

  // The object may be accessed only IMMEDIATELY after PIN authentication
  public static final byte ACCESS_MODE_PIN_ALWAYS = (byte) 0x02;

  // The object may be accessed ALWAYS
  public static final byte ACCESS_MODE_ALWAYS = (byte) 0x7F; // Special value rather than a bitmap
  protected static final short HEADER_ID = (short) 0;
  protected static final short HEADER_MODE_CONTACT = (short) 1;
  protected static final short HEADER_MODE_CONTACTLESS = (short) 2;
  // We allocate some spare header space for derived attributes
  protected static final short LENGTH_HEADER = (short) 8;
  // Linked list element
  public PIVObject nextObject;
  protected final byte[] header;

  protected PIVObject(byte id, byte modeContact, byte modeContactless) {

    header = new byte[LENGTH_HEADER];

    header[HEADER_ID] = id;
    header[HEADER_MODE_CONTACT] = modeContact;
    header[HEADER_MODE_CONTACTLESS] = modeContactless;
  }

  /**
   * Compares the requested identifier value to the current object's id
   *
   * @param id The id to search for
   * @return True if the object matches
   */
  public boolean match(byte id) {
    return (header[HEADER_ID] == id);
  }

  /**
   * Returns the current object's identifier value
   *
   * @return The object identifier
   */
  public byte getId() {
    return header[HEADER_ID];
  }

  /**
   * Returns the ACCESS MODE conditions for the contact interface
   *
   * @return The access mode for the contact interface
   */
  public byte getModeContact() {
    return header[HEADER_MODE_CONTACT];
  }

  /**
   * Returns the ACCESS MODE conditions for the contactless interface
   *
   * @return The access mode for the contactless interface
   */
  public byte getModeContactless() {
    return header[HEADER_MODE_CONTACTLESS];
  }

  /** Requests object deletion if supported by the card. */
  protected void runGc() {
    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }
  }

  /** Clears the current object's value */
  public abstract void clear();

  /** Returns returns true if the object has been initialized. */
  public abstract boolean isInitialised();
}
