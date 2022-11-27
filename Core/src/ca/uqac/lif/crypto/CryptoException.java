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

/**
 * Exception thrown when performing cryptographic operations. As a rule, all
 * other exceptions (except {@link RuntimeException}s) that can be thrown by
 * methods called by objects of this library are caught and wrapped into a
 * {@link CryptoException}.
 * 
 * @author Sylvain Hallé
 */
public class CryptoException extends Exception
{
	/**
	 * Dummy UID.
	 */
	private static final long serialVersionUID = 1L;
	
	/**
	 * Creates a new crypto exception out of a Throwable object.
	 * @param t The Throwable object
	 */
	public CryptoException(Throwable t)
	{
		super(t);
	}
	
	/**
	 * Creates a new crypto exception out of a message.
	 * @param s The message
	 */
	public CryptoException(String s)
	{
		super(s);
	}

}
