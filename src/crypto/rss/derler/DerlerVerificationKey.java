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
package crypto.rss.derler;

import crypto.rss.largeuniverse.LargeUniverseVerificationKey;
import crypto.accumulator.ECCAccumulatorPublicKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * Defines the verification key for the set construction of Derler et. al
 * construction.
 * @author Zach Kissel
 */
public class DerlerVerificationKey extends LargeUniverseVerificationKey
{

  /**
   * Constructs a verification key for the small universe construction.
   * @param apk the accumulator public key.
   * @param pk the signature public key.
   */
   public DerlerVerificationKey(ECCAccumulatorPublicKey apk, PublicKey pk)
   {
      super(apk, pk);
   }

   /**
    * Loads the encoded key from the encoded string.
    * @param encoded the encoded verification key.
    * @throws IllegalArgumentException if the key is invalid.
    */
   public DerlerVerificationKey(byte[] encoded)
      throws IllegalArgumentException
   {
     super(encoded);
   }

  /**
   * Gets the algorithm this key is associated with.
   * @return the algorithm name.
   */
  @Override
  public String getAlgorithm()
  {
    return "derler-set";
  }
}
