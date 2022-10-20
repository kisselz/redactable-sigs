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

import crypto.rss.SetSignature;
import util.DerEncoder;
import util.DerDecoder;
import util.Pair;
import util.Tuple;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.ArrayList;

/**
 * This represenents the signature in the Derler et. al set scheme.
 * @author Zach Kissel
 */
 public class DerlerSetSignature implements SetSignature
 {
   private byte[] acc;      // The accumulator value.
   private byte[] signature;    // The signature on acc and secret.
   private HashMap<String, byte[]> witness;     // The witnesses.

   /**
    * Constructs a new set signature.
    * @param acc the accumulator value.
    * @param signature the signature on acc || secret.
    * @param witness the list of witnesses.
    */
   public DerlerSetSignature(byte[] acc, byte[] signature,
       HashMap<String, byte[]> witness)
   {
     this.acc = acc;
     this.signature = signature;
     this.witness = witness;
   }

   /**
    * Constructs a signature from the DER encoded form.
    * @param encoded the DER encoded set signature.
    * @throws IllegalArgumentException if the DER encoded data is not a
    * valid signature.
    */
    public DerlerSetSignature(byte[] encoded)
        throws IllegalArgumentException
    {
      ArrayList<byte[]> seq = new ArrayList<>();
      ArrayList<byte[]> subseq = new ArrayList<>();

      if (!DerDecoder.isEncodedSequence(encoded))
        throw new IllegalArgumentException("Invalide Signature");

      seq = DerDecoder.decodeSequence(encoded);
      acc = DerDecoder.decodeOctets(seq.get(0));
      signature = DerDecoder.decodeOctets(seq.get(1));
      witness = new HashMap<String, byte[]>();

      // Decode the hash table data.
      subseq = DerDecoder.decodeSequence(seq.get(2));
      for (int i = 0; i < subseq.size(); i++)
      {
        ArrayList<byte[]> record = DerDecoder.decodeSequence(subseq.get(i));
        String key = DerDecoder.decodeString(record.get(0));
        byte[] wit = DerDecoder.decodeOctets(record.get(1));
        witness.put(key, wit);
      }
   }

   /**
    * Gets the accumulator value.
    * @return the accumulator value.
    */
   public byte[] getAccumulator()
   {
     return acc;
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
    public HashMap<String, byte[]> getWitnesses()
    {
      return witness;
    }

   /**
    * Gets the algorithm this key is associated with.
    * @return the algorithm name.
    */
   public String getAlgorithm()
   {
     return "derler-set";
   }

   /**
    * Encodes the signature.
    * @return The DER encoded signature.
    */
    public byte[] getEncoded()
    {
      ArrayList<byte[]> seq = new ArrayList<>();
      ArrayList<byte[]> subseq = new ArrayList<>();

      seq.add(DerEncoder.encodeOctets(acc));
      seq.add(DerEncoder.encodeOctets(signature));

      // Encode the hash table such that we also encode
      // the shares.
      for (String key : witness.keySet())
      {
         ArrayList<byte[]> record = new ArrayList<>();
         record.add(DerEncoder.encodeString(key));
         record.add(DerEncoder.encodeOctets(witness.get(key)));
         subseq.add(DerEncoder.encodeSequence(record));
      }
      seq.add(DerEncoder.encodeSequence(subseq));

      return DerEncoder.encodeSequence(seq);
    }

 }
