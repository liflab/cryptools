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

/**
 * Java implementation of the
 * <a href="https://en.wikipedia.org/wiki/MD5">MD5</a> hash function.
 * 
 * @author Sylvain Hallé
 */
public class MD5 extends JavaHashFunction 
{
	/**
	 * A single publicly visible instance of the hash function.
	 */
	public static final MD5 instance = new MD5();
	
	/**
	 * Creates a new MD5 hash function.
	 */
	protected MD5()
	{
		super(getInstance("MD5"));
	}
}
