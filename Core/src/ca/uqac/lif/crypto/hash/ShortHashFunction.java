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
 * Hash function that generates a digest by truncating the byte array produced
 * by another hash function. The number of bytes <i>n</i> can be specified when
 * instantiating the function, otherwise it defaults to 8. If the underlying
 * function produces a byte array of smaller length, the output is right-padded
 * with zeros.
 * 
 * @author Sylvain Hallé
 *
 * @param <O> The type of objects used as the input of the hash function
 */
public class ShortHashFunction<O> implements HashFunction<O,byte[]>
{
	/**
	 * The hash function used to calculate the original digest.
	 */
	/*@ non_null @*/ protected final HashFunction<O,byte[]> m_innerHash;
	
	/**
	 * The maximum number of bytes to be returned in a digest.
	 */
	protected final int m_maxBytes;
	
	/**
	 * Creates a new short hash function.
	 * @param h The hash function used to calculate the original digest
	 * @param max_bytes The maximum number of bytes to be returned in a digest
	 */
	public ShortHashFunction(/*@ non_null @*/ HashFunction<O,byte[]> h, int max_bytes)
	{
		super();
		m_innerHash = h;
		m_maxBytes = max_bytes;
	}
	
	/**
	 * Creates a new short hash function and limits the number of output bytes
	 * to 8.
	 * @param h The hash function used to calculate the original digest
	 */
	public ShortHashFunction(/*@ non_null @*/ HashFunction<O,byte[]> h)
	{
		this(h, 8);
	}

	@Override
	public byte[] getDigest(O o) throws CryptoException
	{
		byte[] digest = m_innerHash.getDigest(o);
		byte[] out_digest = new byte[m_maxBytes];
		for (int i = 0; i < out_digest.length; i++)
		{
			out_digest[i] = i < digest.length ? digest[i] : 0;
		}
		return out_digest;
	}
}
