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
package ca.uqac.lif.crypto.util;

import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.DoubleStream;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

/**
 * Source of randomness that can be used as the input of key generators.
 * Contrary to its ancestor {@link SecureRandom}, this class is "predictible"
 * in the sense that it guarantees the same sequence of outputs for a given
 * starting seed.
 * <p>
 * It is obviously not recommended to use this class for real-world
 * applications; however, having a predictable and repeatable source of
 * pseudo-random numbers can prove useful for development and testing purposes.
 * 
 * @author Sylvain Hallé
 */
public class PredictableRandom extends SecureRandom
{
	/**
	 * Dummy UID.
	 */
	private static final long serialVersionUID = 1L;

	/*@ non_null @*/ protected Random m_random;

	public PredictableRandom(long seed)
	{
		super();
		m_random = new Random(seed);
	}

	@Override
	public void setSeed(long seed)
	{
		m_random = new Random(seed);
	}

	@Override
	public void nextBytes(byte[] bytes)
	{
		m_random.nextBytes(bytes);
	}

	@Override
	public int nextInt()
	{
		return m_random.nextInt();
	}

	@Override
	public int nextInt(int bound)
	{
		return m_random.nextInt(bound);
	}

	@Override
	public long nextLong()
	{
		return m_random.nextLong();
	}

	@Override
	public float nextFloat()
	{
		return m_random.nextFloat();
	}
	
	@Override
	public double nextGaussian()
	{
		return m_random.nextGaussian();
	}

	@Override
	public boolean nextBoolean()
	{
		return m_random.nextBoolean();
	}

	@Override
	public DoubleStream doubles()
	{
		return m_random.doubles();
	}

	@Override
	public DoubleStream doubles(long stream_size)
	{
		return m_random.doubles(stream_size);
	}

	@Override
	public DoubleStream doubles(double random_number_origin, double random_number_bound)
	{
		return m_random.doubles(random_number_origin, random_number_bound);
	}

	@Override
	public DoubleStream doubles(long stream_size, double random_number_origin, double random_number_bound)
	{
		return m_random.doubles(stream_size, random_number_origin, random_number_bound);
	}

	@Override
	public IntStream ints()
	{
		return m_random.ints();
	}

	@Override
	public IntStream ints(long stream_size)
	{
		return m_random.ints(stream_size);
	}

	@Override
	public IntStream ints(int random_number_origin, int random_number_bound)
	{
		return m_random.ints(random_number_origin, random_number_bound);
	}

	@Override
	public IntStream ints(long stream_size, int random_number_origin, int random_number_bound)
	{
		return m_random.ints(stream_size, random_number_origin, random_number_bound);
	}

	@Override
	public LongStream longs()
	{
		return m_random.longs();
	}

	@Override
	public LongStream longs(long stream_size)
	{
		return m_random.longs(stream_size);
	}

	@Override
	public LongStream longs(long random_number_origin, long random_number_bound)
	{
		return m_random.longs(random_number_origin, random_number_bound);
	}

	@Override
	public LongStream longs(long stream_size, long random_number_origin, long random_number_bound)
	{
		return m_random.longs(stream_size, random_number_origin, random_number_bound);
	}
}
