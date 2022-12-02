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

import ca.uqac.lif.crypto.Key;

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
public class EncryptedObject
{
	/**
	 * The name of the key used to "encrypt" the object.
	 */
	/*@ non_null @*/ protected final String m_keyName;
	
	/**
	 * The "encrypted" object.
	 */
	/*@ non_null @*/ protected final Object m_object;
	
	/**
	 * Creates a new encrypted object.
	 * @param k The key used to "encrypt" the object
	 * @param o The "encrypted" object
	 */
	EncryptedObject(/*@ non_null @*/ Key k, /*@ non_null @*/ Object o)
	{
		super();
		m_keyName = k.getName();
		m_object = o;
	}
	
	/**
	 * Gets the key used to encrypt this object.
	 * @return The key
	 */
	/*@ non_null @*/ public String getKeyName()
	{
		return m_keyName;
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
		return "E[" + m_keyName + "," + m_object.toString() + "]";
	}
	
	@Override
	public int hashCode()
	{
		return m_keyName.hashCode() + m_object.hashCode();
	}
	
	@Override
	public boolean equals(Object o)
	{
		if (!(o instanceof EncryptedObject))
		{
			return false;
		}
		EncryptedObject eo = (EncryptedObject) o;
		return m_keyName.compareTo(eo.m_keyName) == 0 && m_object.equals(eo.m_object);
	}
}