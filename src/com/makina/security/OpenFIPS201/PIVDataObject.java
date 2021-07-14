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
import javacard.framework.Util;

/** Provides functionality for PIV data objects */
public final class PIVDataObject extends PIVObject {

  // Note:  Do NOT use content.length to determine the number of bytes in the content array
  // rather use getLength().
  public byte[] content;
  // Indicates the number of bytes currently allocated.  In the case where an object is
  // reallocated with a smaller size this will be less than content.length
  private short bytesAllocated;

  public PIVDataObject(byte id, byte modeContact, byte modeContactless) {
    super(id, modeContact, modeContactless);
  }

  /**
   * @return the number of bytes allocated in content which may be less than content.length
   */
  public short getLength() {
    return bytesAllocated;
  }

  public void allocate(short length) {
    if (length < 0) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    } else if (length == 0) {
      content = null;
      runGc();
    } else if (content == null) {
      content = new byte[length];
    } else if (length > (short) content.length) {

      // Try to reclaim the resources and re-allocate. If this fails then this card does not
      // support objection deletion and so we can't write an object greater than the initial size
      if (!JCSystem.isObjectDeletionSupported()) ISOException.throwIt(ISO7816.SW_FILE_FULL);

      // Wipe our reference to the data, let the GC collect and re-allocate
      // NOTE: requestObjectDeletion doesn't necessarily do it straight away, so both objects may
      // remain allocated until the next call to process()
      content = null;
      JCSystem.requestObjectDeletion();
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
  public boolean isInitialised() {
    return (content != null);
  }

  /*
   * Wipes all data from the current object
   */
  public void clear() {
    if (content != null) {
      Util.arrayFillNonAtomic(content, (short) 0, (short) content.length, (byte) 0x00);
      bytesAllocated = 0;
    }
  }
}
