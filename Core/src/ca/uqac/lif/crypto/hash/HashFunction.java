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
package ca.uqac.lif.crypto.hash;

import ca.uqac.lif.crypto.CryptoException;

/**
 * Function that produces a digest out of an array of bytes, and which
 * satisfies the conditions of a hash function.
 * 
 * @param <O> The type of the hashed objects
 * @param <H> The type of the computed hash
 * @author Sylvain Hallé
 */
public interface HashFunction<O,H>
{
	/**
	 * Gets a digest out of an input object.
	 * @param o The object
	 * @return The digest
	 * @throws CryptoException Thrown if the digest calculation cannot be
	 * executed
	 */
	/*@ non_null @*/ public H getDigest(/*@ non_null @*/ O o) throws CryptoException;
}
