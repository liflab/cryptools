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
 * Generates keys for a for a symmetric encryption algorithm.
 * @author Sylvain Hallé
 *
 * @param <T> The type of the key contents
 */
public interface KeyGenerator<T>
{
	/**
	 * Generates a new key.
	 * @return The generated key
	 * @throws CryptoException Thrown if the key could not be generated
	 */
	/*@ non_null @*/ public SymmetricKey<T> generateKey() throws CryptoException;
}