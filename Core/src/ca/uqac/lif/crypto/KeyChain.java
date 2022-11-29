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

import java.util.Map;
import java.util.Set;

/**
 * An object associating abstract entities to keys. Note that the sole purpose
 * of the key chain is to handle those associations, and not to protect them or
 * to enforce access control. That is, key chains that are serializable may
 * require the resulting output to be secured by some external means.
 *  
 * @author Sylvain Hallé
 *
 * @param <E> The type of the entities
 * @param <K> The type of the keys contained in this keychain
 */
public interface KeyChain<E,K>
{
	/**
	 * Adds a new entity-key association to this key chain.
	 * @param e The entity
	 * @param k The key
	 * @return This key chain
	 */
	/*@ non_null @*/ public KeyChain<E,K> add(/*@ non_null @*/ E e, /*@ non_null @*/ K k);
	
	/**
	 * Determines if an entity has a key associated to it in this key chain.
	 * @param e The entity to look for
	 * @return <tt>true</tt> if the entity has an associated key,
	 * <tt>false</tt> otherwise
	 */
	/*@ pure @*/ public boolean hasKey(E e);
	
	/**
	 * Gets the key associated to an entity in this key chain.
	 * @param e The entity to look for
	 * @return The key, or <tt>null</tt> if no such key exists
	 */
	/*@ pure null @*/ public K getKey(/*@ non_null @*/ E e);
	
	/**
	 * Gets the set of entities that have a key in this key chain.
	 * @return The set of entities
	 */
	/*@ pure non_null @*/ public Set<E> entitySet();
	
	/**
	 * Gets the set of entries in this key chain.
	 * @return The set of entries
	 */
	/*@ pure non_null @*/ public Set<Map.Entry<E,K>> entrySet();
}
