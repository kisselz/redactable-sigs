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

import crypto.rss.largeuniverse.LargeUniverseVerificationKey;
import crypto.accumulator.AccumulatorPublicKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * Defines the verification key for the small universe construction.
 * @author Zach Kissel
 */
public class SmallUniverseVerificationKey extends LargeUniverseVerificationKey
{
  HashMap<String, Integer> universe;

  /**
   * Constructs a verification key for the small universe construction.
   * @param apk the accumulator public key.
   * @param pk the signature public key.
   * @param universe a description of the universe sets are drawn from.
   */
   public SmallUniverseVerificationKey(AccumulatorPublicKey apk, PublicKey pk,
      HashMap<String, Integer> universe)
   {
      super(apk, pk);
      this.universe = universe;
   }

   /**
    * Loads the encoded key from the encoded string.
    * @param encoded the encoded verification key.
    * @param universe a description of the universe sets are drawn from.
    * @throws IllegalArgumentException if the key is invalid.
    */
   public SmallUniverseVerificationKey(byte[] encoded,
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
