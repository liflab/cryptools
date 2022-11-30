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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ca.uqac.lif.azrael.ObjectPrinter;
import ca.uqac.lif.azrael.ObjectReader;
import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.Printable;
import ca.uqac.lif.azrael.ReadException;
import ca.uqac.lif.azrael.Readable;
import ca.uqac.lif.crypto.Key;
import ca.uqac.lif.crypto.KeyChain;

/**
 * A key chain for Java-based encryption keys.
 * @author Sylvain Hallé
 *
 * @param <E> The type of the entities
 * @param <K> The type of the keys contained in this keychain
 */
public class JavaKeyChain<E,K> implements KeyChain<E,K>, Readable, Printable
{
	/**
	 * The map associating entities with keys.
	 */
	protected final Map<E,K> m_chain;
	
	/**
	 * Creates a new empty key chain.
	 */
	public JavaKeyChain()
	{
		super();
		m_chain = new HashMap<E,K>();
	}
	
	/**
	 * Creates a key chain by copying the contents of another one.
	 * @param chain A map associating entities with keys 
	 */
	protected JavaKeyChain(Map<E,K> chain)
	{
		this();
		m_chain.putAll(chain);
	}
	
	/**
	 * Adds a new entity-key association to this key chain.
	 * @param e The entity
	 * @param k The key
	 * @return This key chain
	 */
	/*@ non_null @*/ public JavaKeyChain<E,K> add(/*@ non_null @*/ E e, /*@ non_null @*/ K k)
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
	/*@ pure null @*/ public K getKey(/*@ non_null @*/ E e)
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
	/*@ pure non_null @*/ public Set<Map.Entry<E,K>> entrySet()
	{
		return m_chain.entrySet();
	}

	@Override
	public Object print(ObjectPrinter<?> printer) throws PrintException
	{
		return printer.print(m_chain);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Object read(ObjectReader<?> reader, Object o) throws ReadException
	{
		Object read = reader.read(o);
		Map<E,K> chain = new HashMap<E,K>();
		if (!(read instanceof Map))
		{
			throw new ReadException("Expected a map");
		}
		for (Map.Entry<?,?> e : ((Map<?,?>) read).entrySet())
		{
			Object k = e.getKey();
			Object v = e.getValue();
			if (!(v instanceof Key))
			{
				throw new ReadException("Expected a key");
			}
			chain.put((E) k, (K) v);
		}
		return new JavaKeyChain<E,K>(chain);
	}
}
