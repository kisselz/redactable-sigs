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

import crypto.rss.largeuniverse.LargeUniverseRedactableSetSignature;
import crypto.rss.smalluniverse.SmallUniverseRedactableSetSignature;
import crypto.rss.derler.DerlerRedactableSetSignature;

/**
 * This object implements a redactble signature scheme factory.
 * @author Zach Kissel
 */
 public class RedactableSetSignatureFactory
 {
   /**
    * Gets a copy of the named redactable set signature scheme.
    * @param algo the name of the algorithm to use.
    * @return a fresh instance of the redactable set signature scheme using
    * the named algo.
    */
   public static RedactableSetSignature getRedactableSetSignature(String algo)
   {
     if (algo.equals("large-universe"))
      return new LargeUniverseRedactableSetSignature();
    else if (algo.equals("small-universe"))
      return new SmallUniverseRedactableSetSignature();
    else if (algo.equals("derler-set"))
      return new DerlerRedactableSetSignature();
    return null;
   }
 }
