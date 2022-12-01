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
 * <a href="https://en.wikipedia.org/wiki/Secure_hash_algorithms">SHA-2</a>
 * hash function.
 * 
 * @author Sylvain Hallé
 */
public class SHA extends JavaHashFunction 
{
	/**
	 * A single publicly visible instance of the SHA-256 function.
	 */
	public static final SHA SHA256 = new SHA("SHA-256");
	
	/**
	 * A single publicly visible instance of the SHA-512function.
	 */
	public static final SHA SHA512 = new SHA("SHA-512");
	
	/**
	 * A single publicly visible instance of the hash function.
	 */
	public static final SHA instance = SHA256;
	
	/**
	 * Creates a new MD5 hash function.
	 */
	protected SHA(String type)
	{
		super(getInstance(type));
	}
}
