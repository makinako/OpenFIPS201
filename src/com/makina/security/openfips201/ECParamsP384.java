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

/**
 * Curve P-384 (aka SECP384R1) domain parameters from NIST SP 800-186
 * (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf) para 4.2.1.4
 */
final class ECParamsP384 {

  private ECParamsP384() {
	
  }

  // The private key length in bytes
  static final short KEY_LENGTH_BYTES = (short)48;

  // The uncompressed public point length
  // NOTE: This is the 2 * KEY_LENGTH_BYTES + 1
  static final short PUBLIC_LENGTH_BYTES = (short)97;

  // cofactor
  static final short H = (short)0x01;

  // Curve polynomial element a
  static final byte[] A = {
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
  };

  // Curve polynomial element b
  static final byte[] B = {
    (byte) 0xB3, (byte) 0x31, (byte) 0x2F, (byte) 0xA7,
    (byte) 0xE2, (byte) 0x3E, (byte) 0xE7, (byte) 0xE4,
    (byte) 0x98, (byte) 0x8E, (byte) 0x05, (byte) 0x6B,
    (byte) 0xE3, (byte) 0xF8, (byte) 0x2D, (byte) 0x19,
    (byte) 0x18, (byte) 0x1D, (byte) 0x9C, (byte) 0x6E,
    (byte) 0xFE, (byte) 0x81, (byte) 0x41, (byte) 0x12,
    (byte) 0x03, (byte) 0x14, (byte) 0x08, (byte) 0x8F,
    (byte) 0x50, (byte) 0x13, (byte) 0x87, (byte) 0x5A,
    (byte) 0xC6, (byte) 0x56, (byte) 0x39, (byte) 0x8D,
    (byte) 0x8A, (byte) 0x2E, (byte) 0xD1, (byte) 0x9D,
    (byte) 0x2A, (byte) 0x85, (byte) 0xC8, (byte) 0xED,
    (byte) 0xD3, (byte) 0xEC, (byte) 0x2A, (byte) 0xEF
  };

  // Base point
  static final byte[] G = {
    (byte) 0x04, (byte) 0xAA, (byte) 0x87, (byte) 0xCA,
    (byte) 0x22, (byte) 0xBE, (byte) 0x8B, (byte) 0x05,
    (byte) 0x37, (byte) 0x8E, (byte) 0xB1, (byte) 0xC7,
    (byte) 0x1E, (byte) 0xF3, (byte) 0x20, (byte) 0xAD,
    (byte) 0x74, (byte) 0x6E, (byte) 0x1D, (byte) 0x3B,
    (byte) 0x62, (byte) 0x8B, (byte) 0xA7, (byte) 0x9B,
    (byte) 0x98, (byte) 0x59, (byte) 0xF7, (byte) 0x41,
    (byte) 0xE0, (byte) 0x82, (byte) 0x54, (byte) 0x2A,
    (byte) 0x38, (byte) 0x55, (byte) 0x02, (byte) 0xF2,
    (byte) 0x5D, (byte) 0xBF, (byte) 0x55, (byte) 0x29,
    (byte) 0x6C, (byte) 0x3A, (byte) 0x54, (byte) 0x5E,
    (byte) 0x38, (byte) 0x72, (byte) 0x76, (byte) 0x0A,
    (byte) 0xB7, (byte) 0x36, (byte) 0x17, (byte) 0xDE,
    (byte) 0x4A, (byte) 0x96, (byte) 0x26, (byte) 0x2C,
    (byte) 0x6F, (byte) 0x5D, (byte) 0x9E, (byte) 0x98,
    (byte) 0xBF, (byte) 0x92, (byte) 0x92, (byte) 0xDC,
    (byte) 0x29, (byte) 0xF8, (byte) 0xF4, (byte) 0x1D,
    (byte) 0xBD, (byte) 0x28, (byte) 0x9A, (byte) 0x14,
    (byte) 0x7C, (byte) 0xE9, (byte) 0xDA, (byte) 0x31,
    (byte) 0x13, (byte) 0xB5, (byte) 0xF0, (byte) 0xB8,
    (byte) 0xC0, (byte) 0x0A, (byte) 0x60, (byte) 0xB1,
    (byte) 0xCE, (byte) 0x1D, (byte) 0x7E, (byte) 0x81,
    (byte) 0x9D, (byte) 0x7A, (byte) 0x43, (byte) 0x1D,
    (byte) 0x7C, (byte) 0x90, (byte) 0xEA, (byte) 0x0E,
    (byte) 0x5F
  };

  // Field Definition
  static final byte[] P = {
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
  };

  // Order of G
  static final byte[] N = {
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xC7, (byte) 0x63, (byte) 0x4D, (byte) 0x81,
    (byte) 0xF4, (byte) 0x37, (byte) 0x2D, (byte) 0xDF,
    (byte) 0x58, (byte) 0x1A, (byte) 0x0D, (byte) 0xB2,
    (byte) 0x48, (byte) 0xB0, (byte) 0xA7, (byte) 0x7A,
    (byte) 0xEC, (byte) 0xEC, (byte) 0x19, (byte) 0x6A,
    (byte) 0xCC, (byte) 0xC5, (byte) 0x29, (byte) 0x73
  };
}
