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
package ca.uqac.lif.crypto.symmetric;

/**
 * The encapsulation of an object of type <tt>T</tt> into an encrypted
 * object of type <tt>E</tt>  
 * @author sylvain
 * 
 * @param <T> The type of the object
 * @param <E> The type of the encrypted version of the object
 */
public interface EncryptedObject<T,E>
{
	/**
	 * Gets the encrypted form of the object.
	 * @return The encrypted form
	 */
	public E getEncrypted();
}
