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
 * Converts a symmetric encryption key to and from an array of bytes.
 * @author Sylvain Hallé
 *
 * @param <K> The key type handled by this converter
 */
public interface ByteKeyConverter<K extends SymmetricKey>
{
	/**
	 * Gets the bytes from a key.
	 * @param key The key
	 * @return The bytes
	 * @throws CryptoException If the bytes could not be recovered from the key
	 */
	/*@ non_null @*/ public byte[] getBytes(/*@ non_null @*/ K key) throws CryptoException;
	
	/**
	 * Gets a key from its byte contents.
	 * @param contents The bytes
	 * @return The key
	 * @throws CryptoException If the key could not be recovered from the bytes
	 */
	/*@ non_null @*/ public K getKey(/*@ non_null @*/ byte[] contents);
}
