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
package ca.uqac.lif.crypto;

/**
 * Converts a key to and from an array of bytes.
 * @author Sylvain Hallé
 *
 * @param <K> The key type
 */
public interface KeySerializer<T>
{
	/**
	 * Converts a key to an array of bytes.
	 * @param k The key
	 * @return The array of bytes
 	 * @throws CryptoException Thrown if the key cannot be converted to an
	 * array of bytes
	 */
	/*@ non_null @*/ byte[] getBytes(Key<T> k) throws CryptoException;
	
	/**
	 * Converts an array of bytes to a key.
	 * @param b The arra of bytes
	 * @return The key
	 * @throws CryptoException Thrown if the key cannot be obtained from the
	 * array of bytes
	 */
	/*@ non_null @*/public Key<T> getKey(byte[] b) throws CryptoException;
}
