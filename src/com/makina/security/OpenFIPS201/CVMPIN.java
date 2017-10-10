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
import org.globalplatform.*;

/**
 * Provides an OwnerPIN proxy to the CVM class to allow uniform handling
 */
public final class CVMPIN extends OwnerPIN {

    CVM cvm;

    /**
     * Constructor
     */
    public CVMPIN(byte tryLimit, byte maxPINSize) throws PINException {

        super(tryLimit, maxPINSize);

        // Get our CVM reference
        cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);

        // Map the try limit to the CVM
        // NOTE: If the applet does not have the CVM MANAGEMENT privilege, this will fail
        if (Config.FEATURE_PIN_GLOBAL_CHANGE) cvm.setTryLimit(tryLimit);
    }

    public byte getTriesRemaining() {
        return cvm.getTriesRemaining();
    }

    public boolean check(byte[] pin, short offset, byte length)
    throws ArrayIndexOutOfBoundsException, NullPointerException {
        return (CVM.CVM_SUCCESS == cvm.verify(pin, offset, length, CVM.FORMAT_HEX));
    }

    public boolean isValidated() {
        return cvm.isVerified();
    }

    public void reset() {
        cvm.resetState();
    }

    public void update(byte[] pin, short offset, byte length)
    throws PINException {
        cvm.update(pin, offset, length, CVM.FORMAT_HEX);
    }

    public void resetAndUnblock() {
        cvm.resetAndUnblockState();
    }

}
