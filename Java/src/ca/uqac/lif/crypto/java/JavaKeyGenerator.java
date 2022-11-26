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

import javax.crypto.SecretKey;

import ca.uqac.lif.crypto.symmetric.KeyGenerator;

abstract class JavaKeyGenerator implements KeyGenerator<SecretKey>
{
	/*@ non_null @*/ protected final javax.crypto.KeyGenerator m_generator;
	
	/*@ null @*/ protected final SecureRandom m_random;
	
	public JavaKeyGenerator(String algorithm, SecureRandom random)
	{
		super();
		m_generator = getInstance(algorithm);
		m_random = random;
	}
	
	public JavaKeyGenerator(String algorithm)
	{
		this(algorithm, null);
	}
		
	@Override
	public String toString()
	{
		return "Key generator for " + m_generator.getAlgorithm();
	}
	
	protected static javax.crypto.KeyGenerator getInstance(String algorithm)
	{
		try 
		{
			return javax.crypto.KeyGenerator.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException e)
		{
			return null;
		}
	}
}
