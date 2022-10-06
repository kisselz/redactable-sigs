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
package crypto.rss.largeuniverse;

import crypto.rss.SetSignature;
import util.DerEncoder;
import util.DerDecoder;
import util.Pair;
import util.Tuple;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Base64;
import java.util.ArrayList;

/**
 * This represenents the large universe signature on a set.
 * @author Zach Kissel
 */
 public class LargeUniverseSetSignature implements SetSignature
 {
   private BigInteger acc;      // The accumulator value.
   private String policy;       // The redaction policy.
   private byte[] signature;    // The signature on acc and secret.
   private HashMap<String, BigInteger> witness;     // The witnesses.
   private HashMap<String,Pair<BigInteger>> shares; // The shares of secret.

   /**
    * Constructs a new set signature.
    * @param acc the accumulator value.
    * @param policy the redaction policy.
    * @param signature the signature on acc || secret.
    * @param witness the list of witnesses.
    * @param shares the shares associated with each element.
    */
   public LargeUniverseSetSignature(BigInteger acc, String policy, byte[] signature,
       HashMap<String, BigInteger> witness,
       HashMap<String, Pair<BigInteger>> shares)
   {
     this.acc = acc;
     this.policy = policy;
     this.signature = signature;
     this.witness = witness;
     this.shares = shares;
   }

   /**
    * Constructs a signature from the DER encoded form.
    * @param encoded the DER encoded set signature.
    * @throws IllegalArgumentException if the DER encoded data is not a
    * valid signature.
    */
    public LargeUniverseSetSignature(byte[] encoded)
        throws IllegalArgumentException
    {
      ArrayList<byte[]> seq = new ArrayList<>();
      ArrayList<byte[]> subseq = new ArrayList<>();

      if (!DerDecoder.isEncodedSequence(encoded))
        throw new IllegalArgumentException("Invalide Signature");

      seq = DerDecoder.decodeSequence(encoded);
      acc = DerDecoder.decodeBigInteger(seq.get(0));
      policy = DerDecoder.decodeString(seq.get(1));
      signature = DerDecoder.decodeOctets(seq.get(2));
      witness = new HashMap<String, BigInteger>();
      shares = new HashMap<String, Pair<BigInteger>>();

      // Decode the hash table data.
      subseq = DerDecoder.decodeSequence(seq.get(3));
      for (int i = 0; i < subseq.size(); i++)
      {
        ArrayList<byte[]> record = DerDecoder.decodeSequence(subseq.get(i));

        String key = DerDecoder.decodeString(record.get(0));
        BigInteger x = DerDecoder.decodeBigInteger(record.get(1));
        BigInteger y = DerDecoder.decodeBigInteger(record.get(2));
        BigInteger wit = DerDecoder.decodeBigInteger(record.get(3));

        if (x.compareTo(BigInteger.ZERO) == 0 &&
           y.compareTo(BigInteger.ZERO) == 0)
            witness.put(key + ":(0, 0)", wit);
        else
        {
          shares.put(key, new Pair<BigInteger>(x, y));
          witness.put(key + ":" + shares.get(key), wit);
        }
      }
    }

   /**
    * Gets the accumulator value.
    * @return the accumulator value.
    */
   public BigInteger getAccumulator()
   {
     return acc;
   }

   /**
    * Gets the redaction policy.
    * @return the redaction policy.
    */
    public String getPolicy()
    {
      return policy;
    }

    /**
     * Gets the signature.
     * @return the signature on acc || secret.
     */
    public byte[] getSignature()
    {
      return signature;
    }

   /**
    * Gets the list of witnesses.
    * @return the list of witnesses.
    */
    public HashMap<String, BigInteger> getWitnesses()
    {
      return witness;
    }

   /**
    * Get the shares associated with the labels.
    * @return the shares associated with the labels.
    */
    public HashMap<String, Pair<BigInteger>> getShares()
    {
      return shares;
    }

   /**
    * Gets the algorithm this key is associated with.
    * @return the algorithm name.
    */
   public String getAlgorithm()
   {
     return "large-universe-set";
   }

   /**
    * Encodes the signature
    * @return the DER encoded form of the signature.
    */
    public byte[] getEncoded()
    {
      ArrayList<byte[]> seq = new ArrayList<>();
      ArrayList<byte[]> subseq = new ArrayList<>();

      seq.add(DerEncoder.encodeBigInteger(acc));
      seq.add(DerEncoder.encodeString(policy));
      seq.add(DerEncoder.encodeOctets(signature));

      // Encode the hash table such that we also encode
      // the shares.
      for (String key : witness.keySet())
      {
         ArrayList<byte[]> record = new ArrayList<>();
         record.add(DerEncoder.encodeString(key.split(":")[0]));
         String[] pt = key.split(":")[1].split(",");
         pt[0] = pt[0].substring(1).strip();
         pt[1] = pt[1].substring(0, pt[1].length() - 1).strip();
         record.add(DerEncoder.encodeBigInteger(new BigInteger(pt[0])));
         record.add(DerEncoder.encodeBigInteger(new BigInteger(pt[1])));
         record.add(DerEncoder.encodeBigInteger(witness.get(key)));
         subseq.add(DerEncoder.encodeSequence(record));
      }
      seq.add(DerEncoder.encodeSequence(subseq));

      return DerEncoder.encodeSequence(seq);
    }

 }
