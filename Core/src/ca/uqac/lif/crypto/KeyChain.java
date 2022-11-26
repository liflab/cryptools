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
package ca.uqac.lif.crypto;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * An object associating abstract entities to keys. Additionally, a key chain
 * can be loaded from, and saved to, a {@link FileSystem} instance.
 * @author Sylvain Hallé
 *
 * @param <E> The type of the entities
 * @param <T> The type of the keys contained in this keychain
 */
public abstract class KeyChain<E,T>
{
	/**
	 * The map storing the associations between entities and keys.
	 */
	/*@ non_null @*/ protected final Map<E,Key<T>> m_chain;
	
	/**
	 * Creates a new empty key chain.
	 */
	public KeyChain()
	{
		super();
		m_chain = new HashMap<E,Key<T>>();
	}
	
	/**
	 * Adds a new entity-key association to this key chain.
	 * @param e The entity
	 * @param k The key
	 * @return This key chain
	 */
	/*@ non_null @*/ public KeyChain<E,T> add(/*@ non_null @*/ E e, /*@ non_null @*/ Key<T> k)
	{
		m_chain.put(e, k);
		return this;
	}
	
	/**
	 * Determines if an entity has a key associated to it in this key chain.
	 * @param e The entity to look for
	 * @return <tt>true</tt> if the entity has an associated key,
	 * <tt>false</tt> otherwise
	 */
	/*@ pure @*/ public boolean hasKey(E e)
	{
		return m_chain.containsKey(e);
	}
	
	/**
	 * Gets the key associated to an entity in this key chain.
	 * @param e The entity to look for
	 * @return The key, or <tt>null</tt> if no such key exists
	 */
	/*@ pure null @*/ public Key<T> getKey(/*@ non_null @*/ E e)
	{
		return m_chain.getOrDefault(e, null);
	}
	
	/**
	 * Gets the set of entities that have a key in this key chain.
	 * @return The set of entities
	 */
	/*@ pure non_null @*/ public Set<E> entitySet()
	{
		return m_chain.keySet();
	}
	
	/**
	 * Gets the set of entries in this key chain.
	 * @return The set of entries
	 */
	/*@ pure non_null @*/ public Set<Map.Entry<E,Key<T>>> entrySet()
	{
		return m_chain.entrySet();
	}
}
