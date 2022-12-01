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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import ca.uqac.lif.crypto.asymmetric.KeyPairGenerator;

/**
 * A key generator for asymmetric encryption algorithms, leveraging Java's
 * {@link KeyPairGenerator} class.
 * 
 * @author Sylvain Hallé
 */
abstract class JavaKeyPairGenerator implements KeyPairGenerator
{
	/**
	 * The underlying generator for key pairs.
	 */
	/*@ null @*/ protected final java.security.KeyPairGenerator m_generator;
	
	/**
	 * An optional secure source of randomness to generate the keys.
	 */
	/*@ null @*/ protected final SecureRandom m_random;
	
	/**
	 * Creates a new key pair generator.
	 * @param algorithm The name of the algorithm to generate keys for
	 * @param random An optional secure source of randomness to generate the
	 * keys; may be null
	 */
	public JavaKeyPairGenerator(/*@ non_null @*/ String algorithm, /*@ null @*/ SecureRandom random)
	{
		super();
		m_generator = getInstance(algorithm);
		m_random = random;
	}
	
	/**
	 * Creates a new key generator.
	 * @param algorithm The name of the algorithm to generate keys for
	 */
	public JavaKeyPairGenerator(/*@ non_null @*/ String algorithm)
	{
		this(algorithm, null);
	}
		
	@Override
	public String toString()
	{
		return "Key pair generator for " + m_generator.getAlgorithm();
	}
	
	/**
	 * Gets an instance of key pair generator based on an algorithm name.
	 * @param algorithm The name of the algorithm to generate key pairs for
	 * @return The generator, or <tt>null</tt> if the algorithm name does not
	 * correspond to an implemented key pair generator
	 */
	/*@ null @*/ protected static java.security.KeyPairGenerator getInstance(String algorithm)
	{
		try 
		{
			return java.security.KeyPairGenerator.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}
