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

import crypto.rss.smalluniverse.SmallUniverseSigningKey;
import crypto.rss.smalluniverse.SmallUniverseVerificationKey;
import crypto.rss.largeuniverse.LargeUniverseSigningKey;
import crypto.rss.largeuniverse.LargeUniverseVerificationKey;
import crypto.rss.derler.DerlerVerificationKey;
import crypto.rss.derler.DerlerSigningKey;
import java.util.HashMap;

/**
 * A redactable signature key factory for building keys from encoded form.
 * @author Zach Kissel
 */
 public class RedactableSetSignatureKeyFactory
 {
   /**
    * Builds the appropriate signature key from {@code algo} and
    * the encoded data.
    * @param algo the redactable signature algorithm.
    * @param encoded the encoded key data.
    * @param universe an optional universe for the set.
    * @return the signing key built from the encoded data.
    */
   public static SigningKey getSigningKey(String algo, byte[] encoded,
      HashMap<String, Integer> universe)
   {
     if (algo.equals("small-universe"))
        return new SmallUniverseSigningKey(encoded, universe);
     else if (algo.equals("large-universe"))
       return new LargeUniverseSigningKey(encoded);
     else if (algo.equals("derler-set"))
       return new DerlerSigningKey(encoded);
     return null;
   }

   /**
    * Builds the appropriate verification key from {@code algo} and the
    * encoded data.
    * @param algo the redactable signature algorithm.
    * @param encoded the encoded key data.
    * @param universe an optional universe for the set.
    * @return the verification key built from the encoded data.
    */
   public static VerificationKey getVerificationKey(String algo, byte[] encoded,
      HashMap<String, Integer> universe)
   {
     if (algo.equals("small-universe"))
        return new SmallUniverseVerificationKey(encoded, universe);
     else if (algo.equals("large-universe"))
       return new LargeUniverseVerificationKey(encoded);
     else if (algo.equals("derler-set"))
       return new DerlerVerificationKey(encoded);
     return null;
   }
 }
