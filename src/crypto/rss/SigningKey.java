/*
 *   Policy-Based Redactable Set Signature Schemes
 *   Copyright (C) 2022  Zachary A. Kissel
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package crypto.rss;

/**
 * Defines a simple signing key interface.
 * @author Zach Kissel
 */
public interface SigningKey
{
  /**
   * Gets the algorithm this key is associated with.
   * @return the algorithm name.
   */
  public String getAlgorithm();

  /**
   * Get the encoded version of the key.
   * @return the key DER encoded.
   */
   public byte[] getEncoded();
}
