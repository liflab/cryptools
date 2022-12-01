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
		if (!k.equals(eo.m_key))
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
	
	/**
	 * An object representing the fictitious "encryption" of a value with a
	 * symmetric key. The resulting object only stores the key <i>K</i> and the
	 * original object <i>O</i>, and its string representation is
	 * "E[<i>K</i>,<i>O</i>]".
	 * <p>
	 * Despite this, an encrypted object is expected to mimic some of the
	 * properties of an actually encrypted value: two such objects are considered
	 * equal if and only if they contain the same internal object encrypted with
	 * the same key.
	 */
	public static class EncryptedObject
	{
		/**
		 * The key used to "encrypt" the object.
		 */
		/*@ non_null @*/ protected final DummySymmetricKey m_key;
		
		/**
		 * The "encrypted" object.
		 */
		/*@ non_null @*/ protected final Object m_object;
		
		/**
		 * Creates a new encrypted object.
		 * @param k The key used to "encrypt" the object
		 * @param o The "encrypted" object
		 */
		EncryptedObject(/*@ non_null @*/ DummySymmetricKey k, /*@ non_null @*/ Object o)
		{
			super();
			m_key = k;
			m_object = o;
		}
		
		/**
		 * Gets the key used to encrypt this object.
		 * @return The key
		 */
		/*@ non_null @*/ public DummySymmetricKey getKey()
		{
			return m_key;
		}
		
		/**
		 * Gets the object that is supposedly encrypted.
		 * @return The object
		 */
		/*@ non_null @*/ public Object getObject()
		{
			return m_object;
		}
		
		@Override
		public String toString()
		{
			return "E[" + m_key.getName() + "," + m_object.toString() + "]";
		}
		
		@Override
		public int hashCode()
		{
			return m_key.hashCode() + m_object.hashCode();
		}
		
		@Override
		public boolean equals(Object o)
		{
			if (!(o instanceof EncryptedObject))
			{
				return false;
			}
			EncryptedObject eo = (EncryptedObject) o;
			return m_key.equals(eo.m_key) && m_object.equals(eo.m_object);
		}
	}
}
