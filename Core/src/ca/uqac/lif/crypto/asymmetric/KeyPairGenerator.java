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
package ca.uqac.lif.crypto.asymmetric;

import ca.uqac.lif.crypto.CryptoException;

/**
 * Generates key pairs for an asymmetric encryption algorithm.
 * @author Sylvain Hallé
 */
public interface KeyPairGenerator
{
	/**
	 * Generates a new public-private key pair.
	 * @return The generated key pair
	 * @throws CryptoException Thrown if the key could not be generated
	 */
	/*@ non_null @*/ public KeyPair generateKeyPair() throws CryptoException;
	
	/**
	 * Generates a new public-private key pair.
	 * @param pu The name given to the public key
	 * @param pr The name given to the private key
	 * @return The generated key pair
	 * @throws CryptoException Thrown if the key could not be generated
	 */
	/*@ non_null @*/ public KeyPair generateKeyPair(/*@ non_null @*/ String pu, /*@ non_null @*/ String pr) throws CryptoException;
}
