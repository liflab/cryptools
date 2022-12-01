/*
  Simple tools for cryptographic operations
  Copyright (C) 2022 Sylvain Hallé
  
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package ca.uqac.lif.crypto.symmetric;

import ca.uqac.lif.crypto.CryptoException;

/**
 * Generates encrypted objects and recovers
 * objects from encrypted objects.
 * 
 * @author Sylvain Hallé
 *
 */
public interface EncryptedObjectFactory
{
	/**
	 * Produces an encrypted object.
	 * @param k The key used for the encryption
	 * @param t The object to encrypt
	 * @return The encrypted object
	 * @throws CryptoException Thrown if the object could not be encrypted
	 */
	/*@ non_null @*/ public EncryptedObject encryptObject(SymmetricKey k, Object t) throws CryptoException;
	
	/**
	 * Recovers an object from an encrypted object.
	 * @param k The key used for the decryption
	 * @param e The encrypted object
	 * @return The decrypted object
	 * @throws CryptoException Thrown if the object could not be decrypted
	 */
	/*@ non_null @*/ public Object decryptObject(SymmetricKey k, EncryptedObject e) throws CryptoException;
}
