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
 * A pair of public and private key used by an asymmetric encryption algorithm.
 * Despite its name, a pair of keys may contain only a public key or only a
 * private key.
 * @author Sylvain Hallé
 */
public interface KeyPair<PU extends PublicKey,PR extends PrivateKey>
{
	/**
	 * Gets the private key contained in this key pair.
	 * @return The private key. May be null if no private key is contained
	 * in this pair
	 * @throws CryptoException Thrown if the private key cannot be obtained
	 */
	/*@ null @*/ public PR getPrivateKey() throws CryptoException;
	
	/**
	 * Gets the public key contained in this key pair.
	 * @return The public key. May be null if no public key is contained
	 * in this pair
	 * @throws CryptoException Thrown if the private key cannot be obtained
	 */
	/*@ null @*/ public PU getPublicKey() throws CryptoException;
	
	/**
	 * Gets a new key pair containing only the public key. In such a case the
	 * private key is replaced by null.
	 * @return The new key pair
	 * @throws CryptoException Thrown if the new key pair key cannot be created
	 */
	public KeyPair<PU,PR> getOnlyPublic() throws CryptoException;
}
