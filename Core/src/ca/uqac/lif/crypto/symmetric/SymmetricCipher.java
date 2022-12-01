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
 * Algorithm using the same key for encryption and decryption.
 * @author Sylvain Hallé
 *
 * @param <M> The type of the message handled by the algorithm
 */
public interface SymmetricCipher<M>
{
	/**
	 * Encrypts a message using a key.
	 * @param k The key
	 * @param m The message to encrypt
	 * @return The encrypted message
	 * @throws CryptoException Thrown if the encryption could not proceed
	 */
	/*@ non_null @*/ public M encrypt(SymmetricKey k, M m) throws CryptoException;
	
	/**
	 * Decrypts a message using a key.
	 * @param k The key
	 * @param m The message to decrypt
	 * @return The encrypted message
	 * @throws CryptoException Thrown if the decryption could not proceed
	 */
	public M decrypt(SymmetricKey k, M m) throws CryptoException;
}
