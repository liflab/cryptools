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

import ca.uqac.lif.crypto.CryptoException;

/**
 * A symmetric cipher that performs nothing and returns its input unchanged.
 * This cipher can be used in place of another "real" cipher for testing
 * purposes.
 * 
 * @author Sylvain Hallé
 *
 * @param <M> The type of the message handled by the algorithm
 */
public class NoopSymmetricCipher<M> implements SymmetricCipher<M>
{
	@Override
	public M encrypt(SymmetricKey k, M m) throws CryptoException
	{
		return m;
	}

	@Override
	public M decrypt(SymmetricKey k, M m) throws CryptoException
	{
		return m;
	}
	
	@Override
	public String toString()
	{
		return "Noop";
	}
}
