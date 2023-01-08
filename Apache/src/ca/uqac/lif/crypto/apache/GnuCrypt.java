/*
  Simple tools for cryptographic operations
  Copyright (C) 2022-2023 Sylvain Hallé
  
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
package ca.uqac.lif.crypto.apache;

import org.apache.commons.codec.digest.Crypt;

import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.hash.HashFunction;

/**
 * GNU libc <tt><a href="https://en.wikipedia.org/wiki/Crypt_(C)">crypt(3)</a></tt>
 * compatible hash method. This class uses the implementation from the
 * <a href="https://commons.apache.org/proper/commons-codec/">Apache Commons
 * Codec</a> library.
 * <p>
 * In addition to the {@link #getDigest(String)} method implemented
 * by all hash functions of Cryptools, this function also allows a digest to
 * be calculated by specifying a salt using {@link #getDigest(String, String)}.
 * 
 * @author Sylvain Hallé
 */
public class GnuCrypt implements HashFunction<String,String>
{
	/**
	 * A single publicly visible instance of the hash function.
	 */
	/*@ non_null @*/ public static final GnuCrypt instance = new GnuCrypt();
	
	/**
	 * Creates a new instance of the hash function.
	 */
	protected GnuCrypt()
	{
		super();
	}
	
	@Override
	public String getDigest(String s) throws CryptoException
	{
		try
		{
			return Crypt.crypt(s);
		}
		catch (IllegalArgumentException e)
		{
			throw new CryptoException(e);
		}
	}
	
	/**
	 * Calculates a digest with the <tt>crypt(3)</tt> function by specifying a
	 * salt. This function behaves exactly like Commons Codec's
	 * <a href="https://commons.apache.org/proper/commons-codec/archives/1.15/apidocs/org/apache/commons/codec/digest/Crypt.html#crypt-java.lang.String-java.lang.String-">crypt()</a>
	 * method; follow the link to get information about the format of the salt.
	 * 
	 * @param s The object to get the digest from
	 * @param salt The salt to use in the calculation
	 * @return The string corresponding to the resulting digest
	 * @throws CryptoException Thrown if the digest could not be calculated
	 * for some reason
	 */
	/*@ non_null @*/ public String getDigest(String s, String salt) throws CryptoException
	{
		try
		{
			return Crypt.crypt(s, salt);
		}
		catch (IllegalArgumentException e)
		{
			throw new CryptoException(e);
		}
	}
}
