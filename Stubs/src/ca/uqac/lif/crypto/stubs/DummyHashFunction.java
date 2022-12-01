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
package ca.uqac.lif.crypto.stubs;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.hash.HashFunction;

/**
 * A hash function that simulates the hashing of a value without performing any
 * actual calculation.
 * 
 * @author Sylvain Hallé
 */
public class DummyHashFunction implements HashFunction<Object,ca.uqac.lif.crypto.stubs.DummyHashFunction.HashValue>
{
	/**
	 * A single publicly visible instance of the dummy hash function.
	 */
	public static final DummyHashFunction instance = new DummyHashFunction();
	
	@Override
	public HashValue getDigest(Object o) throws CryptoException
	{
		return new HashValue(o);
	}
	
	/**
	 * An object representing the fictitious "hashing" of a value with a hash
	 * function. The object only stores the original value <i>O</i>, and its
	 * string representation is "H(<i>O</i>)".
	 */
	public static class HashValue
	{
		/**
		 * The value to be hashed.
		 */
		/*@ non_null @*/ protected Object m_value;

		/**
		 * Creates a new hash value.
		 * @param value The value to be hashed.
		 */
		public HashValue(/*@ non_null @*/ Object value)
		{
			super();
			m_value = value;
		}

		@Override
		public String toString()
		{
			return "H(" + m_value.toString() + ")";
		}

		@Override
		public int hashCode()
		{
			return m_value.hashCode();
		}

		@Override
		public boolean equals(Object o)
		{
			if (!(o instanceof HashValue))
			{
				return false;
			}
			return m_value.equals(((HashValue) o).m_value);
		}
	}
	
	@Override
	public String toString()
	{
		return "Dummy";
	}
}
