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
import javacard.framework.Util;

/** Provides functionality for PIV data objects */
final class PIVDataObject extends PIVObject {

  // NOTES:
  // - We deliberately make this public to provide access via ChainBuffer, etc. It isn't good OO
  //   but it's Java Card so we forgive ourselves.
  // - Do NOT use content.length to determine the number of bytes in the content array rather use
  //   getLength().
  byte[] content;

  // Indicates the number of bytes currently allocated.  In the case where an object is
  // reallocated with a smaller size this will be less than content.length
  private short bytesAllocated;

  PIVDataObject(byte id, byte modeContact, byte modeContactless, byte adminKey) {
    super(id, modeContact, modeContactless, adminKey, (byte) 0);
  }

  /**
   * @return the number of bytes allocated in content which may be less than content.length
   */
  short getLength() {
    return bytesAllocated;
  }

  void allocate(short length) throws ISOException {

    if (length <= (short) 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (content == null) {
      content = new byte[length];
    } else if (length > (short) content.length) {
      // Try to reclaim the resources and re-allocate. If this fails then this card does not
      // support objection deletion and so we can't write an object greater than the initial size
      if (!JCSystem.isObjectDeletionSupported()) ISOException.throwIt(ISO7816.SW_FILE_FULL);

      clear();
      content = new byte[length];
    } else {
      // Just clear the content object
      Util.arrayFillNonAtomic(content, (short) 0, (short) content.length, (byte) 0x00);
    }
    bytesAllocated = length;
  }

  /**
   * Returns true if this object is populated with data
   *
   * @return True if the object is initialised
   */
  boolean isInitialised() {
    return (content != null);
  }

  /*
   * Wipes all data from the current object
   */
  void clear() {
    if (content == null) return;

    PIVSecurityProvider.zeroise(content, (short) 0, (short) content.length);
    bytesAllocated = 0;

    // Wipe our reference to the data, let the GC collect and re-allocate
    // NOTE: requestObjectDeletion doesn't necessarily do it straight away, so both objects may
    // remain allocated until the next call to process()
    if (JCSystem.isObjectDeletionSupported()) {
      content = null;
      JCSystem.requestObjectDeletion();
    }
  }
}
