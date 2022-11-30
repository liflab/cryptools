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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import ca.uqac.lif.crypto.hash.HashFunction;

/**
 * A hash function based on Java's {@link MessageDigest} class.
 * 
 * @author Sylvain Hallé
 */
abstract class JavaHashFunction implements HashFunction<byte[],byte[]>
{
	/**
	 * The MessageDigest object used to compute hash values.
	 */
	/*@ null @*/ protected final MessageDigest m_digest;
	
	/**
	 * Creates a new Java hash function.
	 * @param digest The MessageDigest object used to compute hash values
	 */
	protected JavaHashFunction(/*@ non_null @*/ MessageDigest digest)
	{
		super();
		m_digest = digest;
	}
	
	@Override
	public byte[] getDigest(byte[] m)
	{
		m_digest.update(m);
		return m_digest.digest();
	}
	
	@Override
	public String toString()
	{
		return m_digest.getAlgorithm();
	}
	
	/**
	 * Gets the message digest object based on an algorithm name.
	 * @param algorithm The name of the hashing algorithm
	 * @return The instance, or <tt>null</tt> if no such algorithm exists
	 */
	protected static MessageDigest getInstance(String algorithm)
	{
		try
		{
			return MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}
