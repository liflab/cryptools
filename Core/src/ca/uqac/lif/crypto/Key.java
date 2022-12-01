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
 * An object used by a cipher to encrypt or decrypt a message. Keys can either
 * be symmetric or asymmetric. Optionally, they can also provide a legible
 * name to distinguish them.
 * 
 * @author Sylvain Hallé
 *
 */
public interface Key
{
	/**
	 * Gets the name of this key.
	 * @return The key's name. If the key has no assigned name, the empty string
	 * is returned.
	 */
	/*@ non_null @*/ public String getName();
}
