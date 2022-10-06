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
package crypto.rss.smalluniverse;

import crypto.rss.largeuniverse.LargeUniverseSigningKey;
import crypto.accumulator.AccumulatorPrivateKey;
import java.security.PrivateKey;
import java.util.HashMap;

/**
 * Defines the signing key for the small universe construction.
 * @author Zach Kissel
 */
public class SmallUniverseSigningKey extends LargeUniverseSigningKey
{
  HashMap<String, Integer> universe;

  /**
   * Constructs a signing key for the small universe construction.
   * @param ask the accumulator private key.
   * @param sk the signing key.
   * @param universe a description of the universe sets are drawn from.
   */
   public SmallUniverseSigningKey(AccumulatorPrivateKey ask, PrivateKey sk,
      HashMap<String, Integer> universe)
   {
      super(ask, sk);
      this.universe = universe;
   }

   /**
    * Loads the encoded key from the encoded string.
    * @param encoded the encoded verification key.
    * @param universe a description of the universe sets are drawn from.
    * @throws IllegalArgumentException if the key is invalid.
    */
   public SmallUniverseSigningKey(byte[] encoded,
      HashMap<String, Integer> universe)
      throws IllegalArgumentException
   {
     super(encoded);
     this.universe = universe;
   }

  /**
   * Gets the universe associated with the set.
   * @return the universe associated with the sets.
   */
  public HashMap<String, Integer> getUniverse()
  {
    return this.universe;
  }

  /**
   * Gets the algorithm this key is associated with.
   * @return the algorithm name.
   */
  @Override
  public String getAlgorithm()
  {
    return "small-universe-set";
  }
}
