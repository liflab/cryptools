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
import ca.uqac.lif.crypto.symmetric.KeyGenerator;
import ca.uqac.lif.crypto.symmetric.ObjectSymmetricCipher;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

/**
 * A cipher that simulates the encryption of an object without performing any
 * actual encryption.
 * 
 * @author Sylvain Hallé
 */
public class DummySymmetricCipher implements ObjectSymmetricCipher<ca.uqac.lif.crypto.stubs.DummySymmetricCipher.DummySymmetricKey>
{
	/**
	 * A single publicly visible instance of the dummy symmetric cipher.
	 */
	public static final DummySymmetricCipher instance = new DummySymmetricCipher();
	
	/**
	 * A static reference to an instance of DES key generator with default
	 * settings.
	 */
	public static final DummyKeyGenerator generator = new DummyKeyGenerator();
	
	/**
	 * Creates a new instance of the cipher.
	 */
	protected DummySymmetricCipher()
	{
		super();
	}
	
	@Override
	public Object encrypt(DummySymmetricKey k, Object m) throws CryptoException
	{
		return new EncryptedObject(k, m);
	}

	@Override
	public Object decrypt(DummySymmetricKey k, Object m) throws CryptoException
	{
		if (!(m instanceof EncryptedObject))
		{
			throw new CryptoException("Invalid input object type");
		}
		EncryptedObject eo = (EncryptedObject) m;
		if (k.getName().compareTo(eo.getKeyName()) != 0)
		{
			throw new CryptoException("Cannot decrypt object");
		}
		return eo.m_object;
	}
	
	@Override
	public String toString()
	{
		return "Dummy";
	}
	
	/**
	 * A dummy symmetric encryption key.
	 */
	public static class DummySymmetricKey implements SymmetricKey
	{
		/**
		 * The key's optional name.
		 */
		protected final String m_name;
		
		/**
		 * Creates a "dummy" symmetric encryption key.
		 * @param name The key's name, which is mandatory
		 * @throws CryptoException If the name is null or blank
		 */
		protected DummySymmetricKey(String name) throws CryptoException
		{
			super();
			if (name == null || name.isBlank())
			{
				throw new CryptoException("This key must be given a name");
			}
			m_name = name;
		}
		
		/**
		 * Empty constructor used only for deserialization.
		 */
		protected DummySymmetricKey()
		{
			super();
			m_name = "";
		}
		
		@Override
		public String getName()
		{
			return m_name;
		}
		
		@Override
		public int hashCode()
		{
			return m_name.hashCode();
		}
		
		@Override
		public boolean equals(Object o)
		{
			return o instanceof DummySymmetricKey && m_name.compareTo(((DummySymmetricKey) o).m_name) == 0;
		}
	}
	
	/**
	 * A generator for dummy symmetric encryption keys.
	 */
	protected static class DummyKeyGenerator implements KeyGenerator<DummySymmetricKey>
	{
		@Override
		public DummySymmetricKey generateKey() throws CryptoException
		{
			return generateKey("");
		}

		@Override
		public DummySymmetricKey generateKey(String name) throws CryptoException
		{
			return new DummySymmetricKey(name);
		}
	}
}
