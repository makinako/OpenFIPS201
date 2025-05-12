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

final class PIVDataStore {

  //
  // Persistent Objects
  //

  private PIVContainer firstContainer;
  private PIVKey firstKey;
  private PIVVerifier firstVerifier;

  PIVContainer getContainer(int id) {
    if (firstContainer == null) {
      return null;
    } else {
      return (PIVContainer) firstContainer.select(id);      
    }
  }
  
  PIVContainer getContainerByIndex(short index) {
    PIVObject result = null;
    if (firstContainer != null) {
      result = firstContainer;
      while (index > 0 && result != null) {
        result = result.nextObject;
        index--;
      }
    }
    return (PIVContainer)result;
  }  
  
  void addContainer(PIVContainer container) {
    // NOTE for @spaikmos :)
    // This has been changed back to its original implementation of writing to the
    // TAIL of the list because of the following reasons:
    // - A list traversal and one EEPROM write is faster than two EEPROM writes
    // - A single EEPROM write reduces the risk of tearing and avoids the need for transactions
    if (firstContainer == null) {
      firstContainer = container;
    } else {
      firstContainer.last().nextObject = container;
    }
  }

  PIVKey getKey(byte id) {
    if (firstKey == null) { 
      return null;
    } else {
      // The internal select operates on an int, so we mask off any signed conversion
      return (PIVKey) firstKey.select(id & 0xFF);
    }
  }

  PIVKey getKey(byte id, byte mechanism) {
    if (firstKey == null) { 
      return null;
    } else {
      // The internal select operates on an int, so we mask off any signed conversion
      return firstKey.select(id & 0xFF, mechanism);
    }
  }

  
  PIVKey getKeyByIndex(short index) {
    PIVObject result = null;
    if (firstKey != null) {
      result = firstKey;
      while (index > 0 && result != null) {
        result = result.nextObject;
        index--;
      }
    }
    return (PIVKey)result;
  }  
  
  void addKey(PIVKey key) {
    if (firstKey == null) {
      firstKey = key;
    } else {
      firstKey.last().nextObject = key;
    }
  }  

  PIVVerifier getVerifier(byte id) {
    if (firstVerifier == null) { 
      return null;
    } else {
      // The internal select operates on an int, so we mask off any signed conversion
      return (PIVVerifier) firstVerifier.select(id & 0xFF);
    } 
  }
  
  PIVVerifier getVerifierByIndex(short index) {
    PIVObject result = null;
    if (firstVerifier != null) {
      result = firstVerifier;
      while (index > 0 && result != null) {
        result = result.nextObject;
        index--;
      }
    }
    return (PIVVerifier)result;
  }  

  void resetVerifiers() {
    if (firstVerifier == null) {
      return;
    }
    
    PIVVerifier verifier = firstVerifier;
    while (verifier != null) {
      verifier.reset();
      verifier = (PIVVerifier)verifier.nextObject;
    }
  }

  boolean isGlobalPinPreferred() {    
    // If the global PIN does not exist, it isn't
    PIVObject globalPin = getVerifier(Constants.ID_AUTH_GLOBAL_PIN);
    if (null == globalPin) return false;
    
    // If the local PIN does not exist, prefer existing global
    if (null == getVerifier(Constants.ID_AUTH_LOCAL_PIN)) return true;

    // If the local PIN can be selected from the globalPin linked list, the globalPIN is preferred
    return (globalPin.select(Constants.ID_AUTH_LOCAL_PIN & 0xFF) != null);    
  }
  
  /**
   * Returns true if any of the 'user' verifiers are validated. This does NOT replace the role check
   * but rather is used in concert with it to also check the internal verifier. 
   * @return
   */
  boolean isUserVerified() {
    PIVVerifier globalPin = getVerifier(Constants.ID_AUTH_GLOBAL_PIN);
    PIVVerifier localPin = getVerifier(Constants.ID_AUTH_LOCAL_PIN);
    
    boolean result = false;
    if (localPin != null && localPin.isValidated()) {
      result = true;
    }
    if (globalPin != null && globalPin.isValidated()) {
      result = true;
    }
    
    return result;
  }
  
  void addVerifier(PIVVerifier verifier) {
    if (firstVerifier == null) {
      firstVerifier = verifier;
    } else {
      firstVerifier.last().nextObject = verifier;
    }    
  }
}

