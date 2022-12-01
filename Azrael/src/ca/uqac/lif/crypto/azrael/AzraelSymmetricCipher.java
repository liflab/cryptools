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
package ca.uqac.lif.crypto.azrael;

import ca.uqac.lif.azrael.ObjectPrinter;
import ca.uqac.lif.azrael.ObjectReader;
import ca.uqac.lif.azrael.PrintException;
import ca.uqac.lif.azrael.ReadException;
import ca.uqac.lif.crypto.CryptoException;
import ca.uqac.lif.crypto.symmetric.SymmetricCipher;
import ca.uqac.lif.crypto.symmetric.SymmetricKey;

public abstract class AzraelSymmetricCipher<T,M> implements SymmetricCipher<Object>
{
	/*@ non_null @*/ protected final ObjectPrinter<T> m_printer;
	
	/*@ non_null @*/ protected final ObjectReader<T> m_reader;
	
	/*@ non_null @*/ protected final SymmetricCipher<M> m_cipher;
	
	public AzraelSymmetricCipher(/*@ non_null @*/ ObjectPrinter<T> printer, /*@ non_null @*/ ObjectReader<T> reader, SymmetricCipher<M> cipher)
	{
		super();
		m_printer = printer;
		m_reader = reader;
		m_cipher = cipher;
	}
	
	@Override
	public Object encrypt(SymmetricKey k, Object m) throws CryptoException
	{
		try
		{
			T t = m_printer.print(m);
			M o = convertFrom(t);
			return m_cipher.encrypt(k, o);
		}
		catch (PrintException e)
		{
			throw new CryptoException(e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public Object decrypt(SymmetricKey k, Object m) throws CryptoException
	{
		try
		{
			M decrypted = m_cipher.decrypt(k, (M) m);
			T object = convertTo(decrypted);
			return m_reader.read(object);
		}
		catch (ClassCastException e)
		{
			throw new CryptoException(e);
		}
		catch (ReadException e)
		{
			throw new CryptoException(e);
		}
	}
	
	protected abstract M convertFrom(T t);
	
	protected abstract T convertTo(M m);

}
