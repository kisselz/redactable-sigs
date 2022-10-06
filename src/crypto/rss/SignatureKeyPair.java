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
 * This class implements a basic signature key pair class. It assumes that
 * the signing key and verification key are represented as bytes.
 * @author Zach Kissel
 */
 public class SignatureKeyPair
 {
   private SigningKey sk;
   private VerificationKey vk;

   /**
    * Constructs a new keypair with signing key {@code sk} and
    * verification key {@code vk}.
    * @param sk the signing key.
    * @param vk the verification key.
    */
   public SignatureKeyPair(SigningKey sk, VerificationKey vk)
   {
     this.sk = sk;
     this.vk = vk;
   }

   /**
    * Gets the signing key.
    * @return the associated signing key.
    */
   public SigningKey getSigningKey()
   {
     return this.sk;
   }

   /**
    * Gets the verification key.
    * @return the associated verification key.
    */
   public VerificationKey getVerificationKey()
   {
     return this.vk;
   }

 }
