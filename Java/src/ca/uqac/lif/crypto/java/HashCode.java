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
package ca.uqac.lif.crypto.java;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.hash.ObjectHashFunction;

/**
 * A hash function that takes as input an arbitrary object, and returns as its
 * digest the return value of calling
 * {@link HashCode#hashCode() hashCode()} on this object.
 * 
 * @author Sylvain Hallé
 */
public class HashCode implements ObjectHashFunction
{
	/**
	 * A reference to a single visible instance of the object hash function.
	 */
	/*@ non_null @*/ public static HashCode instance = new HashCode();
	
	/**
	 * Creates a new object has function.
	 */
	protected HashCode()
	{
		super();
	}
	
	@Override
	/*@ non_null @*/ public Integer getDigest(/*@ non_null @*/ Object o) throws CryptoException
	{
		return o.hashCode();
	}
}
