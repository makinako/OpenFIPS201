/******************************************************************************
MIT License

OpenFIPS201 - Copyright (c) 2017 Kim O'Sullivan (Makina)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This software was commissioned by the Australian Department of Defence to
provide an open reference implementation for the Personal Identity Verification
standard (FIPS PUB 201-2 / NIST SP800-73-4) to the public.

BETA RELEASE - Please note that this is an initial release for evaluation
purposes to demonstrate the design and progress of this reference code.

Please provide any feedback to: piv@makina.com.au
******************************************************************************/

package com.makina.security.OpenFIPS201;

import javacard.framework.*;

/**
 * Provides functionality for PIV data objects
 */
public final class PIVDataObject extends PIVObject {

    public byte[] content;

    // Indicates whether this object is populated with data or not
    // It exists to cover the scenario where the data memory is allocated, but the write fails mid-way
    private static final short HEADER_POPULATED = (short)3;

    public PIVDataObject(byte id, byte modeContact, byte modeContactless) {
        super(id, modeContact, modeContactless);
    }

    public void allocate(short length) {

        if (content == null) {
            content = new byte[length];
        } else if (length > (short)content.length) {

            // Try to reclaim the resources and re-allocate. If this fails then this card does not
            // support objection deletion and so we can't write an object greater than the initial size
            if (!JCSystem.isObjectDeletionSupported()) ISOException.throwIt(ISO7816.SW_FILE_FULL);

            // Wipe our reference to the data, let the GC collect and re-allocate
            // NOTE: requestObjectDeletion doesn't necessarily do it straight away, so both objects may remain
            //		 allocated until the next call to process()
            content = null;
            JCSystem.requestObjectDeletion();
            content = new byte[length];
        } else {
            // Just clear the content object
            Util.arrayFillNonAtomic(content, (short)0, (short)content.length, (byte)0x00);
        }
    }

    /**
     * Returns true if this object is populated with data
     */
    public boolean isInitialized() {
        // TODO: Add the HEADER_POPULATED check here once ChainBuffer supports it, to account for
        //		 situations where an object is partially written
        return (content != null);
    }

    /*
     * Wipes all data from the current object
     */
    public void clear() {
        if (content == null) return;
        Util.arrayFillNonAtomic(content, (short)0, (short)content.length, (byte)0x00);
    }

}
