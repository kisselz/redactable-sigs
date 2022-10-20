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


 package crypto.accumulator;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Set;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Arrays;

// JPBC.
// WARNING: field elements  in JPBC are mutable so computation must be handled
// carefully,
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import util.Pair;
import util.Tuple;

/**
 * A partial implementation (no removal or non-membership witnesses) of the
 * dynamic accumulator discussed in:
 *   "Dynamic Universal Accumulator with Batch Update over Bilinear Groups"
 *   by: Giuseppe Vitto and Alex Biryukov
 *
 * NOTE: Unlike the RSA accumulator, a party in possession of the private key
 * can forge a witness for an element that has not been accumulated.
 *
 * @author Zach Kissel
 */
 public class ECCAccumulator
 {
   private ECCAccumulatorPublicKey pk;
   private ECCAccumulatorPrivateKey sk;
   private Field Zp;
   private Field G;

   /**
    * Constructs a new accumulator that uses the the curve SecP256K1 for
    * its group.
    */
   public ECCAccumulator()
   {
     Pairing pairing = PairingFactory.getPairing("pairing.params");
     Zp = pairing.getZr();
     G = pairing.getG1();
   }

   /**
    * Constructs a new KeyPair for the accumulator.
    * @return the accumulator's keypair.
    */
   public static ECCAccumulatorKeyPair keyGen()
   {

     Pairing pairing = PairingFactory.getPairing("pairing.params");
     Field Zp = pairing.getZr();
     Field G = pairing.getG1();

     // Pick a generator for G.
     Element g = G.newRandomElement();

     // Pick the secret key element from Z_p.
     Element sk = Zp.newRandomElement();

     // Compute the public key, an element in G.
     Element pk = g.duplicate();
     pk.powZn(sk);

     return new ECCAccumulatorKeyPair(new ECCAccumulatorPrivateKey(sk, g),
        new ECCAccumulatorPublicKey(pk, g));
   }

   /**
    * Initializes the object for verification.
    * @param pk the public key for the accumulator.
    */
   public void initVerify(ECCAccumulatorPublicKey pk)
   {
     this.sk = null;
     this.pk = pk;
   }

   /**
    * Initializes the object for accumulation.
    * @param sk the private key for the accumulator.
    */
   public void initAccumulate(ECCAccumulatorPrivateKey sk)
   {
     this.pk = null;
     this.sk = sk;
   }

   /**
    * Takes a set of strings as input and produces the accumulator value.
    * @param set a linked list of strings to accumulate.
    * @return the accumulator value as a byte array.
    * @throws UnsupportedOperationException if the object has not been
    * initialized for accumulation.
    */
   public byte[] eval(Set<String> set)
      throws UnsupportedOperationException
   {
     Element g = sk.getGenerator().duplicate();
     Element secret = sk.getSecret();
     Element prod = Zp.newOneElement();

     if (sk == null)
       throw new UnsupportedOperationException("Call initAccumulate first.");

     for (String ele : set)
     {
       // Hash to an element of Z_p.
       Element hash = Zp.newElementFromHash(ele.getBytes(), 0,
           ele.getBytes().length);

       // Update the product.
       hash.add(secret);
       prod.mul(hash);
     }

     // Compute the accumulator value.
     g.powZn(prod);

     return g.toBytes();
   }

   /**
    * Generates the witeness for a element ele. NOTE: The scheme allows the
    * accumulator generator to forge witnesses.
    * @param ele the element to generate the witness for.
    * @param acc the accumulator value.
    * @return the witness for the element.
    * @throws UnsupportedOperationException if the object has not been
    * initialized for accumulation.
    */
   public byte[] getWitness(String ele, byte[] acc)
      throws UnsupportedOperationException
   {
     Element g = sk.getGenerator();
     Element secret = sk.getSecret();
     Element av = G.newElementFromBytes(acc);  // Construct a new element in group G.
     Element wit;

     if (sk == null)
       throw new UnsupportedOperationException("Call initAccumulate first.");

     // Hash to an element of Z_p and add the secret value.
     // Hash to an element of Z_p.
     Element hash = Zp.newElementFromHash(ele.getBytes(), 0,
        ele.getBytes().length);
     hash.add(secret);

     // Find the elements inverse.
     Element inv = hash.duplicate();
     inv.invert();

     // Compute the witness value.
     av.powZn(inv);

     return av.toBytes();
   }

   /**
    * Determines if the element is in the accumulator given the witness.
    * @param acc the accumulator value.
    * @param witness the value of the witness.
    * @param ele the element associated with the witness.
    * @return true if the {@code ele} is in the accumulator; otherwise, false.
    * @throws UnsupportedOperationException if the object has not been
    * initialized for verification.
    */
   public boolean verify(byte[] acc, byte[] witness, String ele)
       throws UnsupportedOperationException
   {
     Element av = G.newElementFromBytes(acc);
     Element wit = G.newElementFromBytes(witness);
     Element g = pk.getGenerator().duplicate();
     Pairing pairing = PairingFactory.getPairing("pairing.params");

     if (pk == null)
      throw new UnsupportedOperationException("Call initVerify first.");

     // Hash to an element of Z_p.
     Element hash = Zp.newElementFromHash(ele.getBytes(), 0,
        ele.getBytes().length);

     // Execute the two pairings if they are equal the
     // witness is valid. Otherwise, the witness is invalid.
     Element second = g.powZn(hash);
     second.add(pk.getPublic());
     Element left = pairing.pairing(wit, second);
     av.invert();
     Element right = pairing.pairing(av, pk.getGenerator());
     left.mul(right);

    return left.isOne();
   }
 }
