package datastructures.bloom;

import java.util.BitSet;
import java.util.Arrays;

/**
 * This file implements a simple Bloom filter.
 * @author Zach Kissel
 */
 public class BloomFilter
 {
   int maxEntries;      // The maximum number of entries.
   BitSet filter;       // The filter as a BitSet object.
   int numHashes;       // The number of hash functions to use.
   /**
    * Constructs a Bloom filter that can hold {@code maxEntries} with a
    * false postive rate of {@code fpr}.
    * @param maxEntries the maximum number of entries to be placed in the filter.
    * @param fpr the false positive rate of the filter.
    */
   public BloomFilter(int maxEntries, double fpr)
   {
      this.maxEntries = maxEntries;

      // Formula from: https://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
      int numBits = (int)(-maxEntries * Math.log(fpr)/(Math.log(2) * Math.log(2)));
      this.filter = new BitSet(numBits);

      // Formula from: https://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
      numHashes = Math.max(1, (int) Math.round((double)(numBits / maxEntries) * Math.log(2)));
   }

   /**
    * Checks if the given data is found in the Bloom filter. As this is a Bloom
    * filter, there is a probability of a false positive. Hashing is done using
    * double hashing as analyzed by Kirsh and Mitzenmacher
    *
    * @param data the data to check.
    * @return true if the data is in the filter and false otherwise.
    */
   public boolean contains(byte[] data)
   {
     int[] h = hashValues(data);

     // Check to see if all of the bits are set.
     for (int i = 1; i <= numHashes; i++)
        if (!this.filter.get(getIndex(h[0], h[1], i)))
           return false;

     // If we've made it this far, all bits are set; return true.
     return true;
   }

   /**
    * Adds data to the filter.
    * @param data the data to add to the filter.
    */
   public void add(byte[] data)
   {
     int[] h = hashValues(data);
     int index;

     // Set the necessary bits of the filter.
     for (int i = 1; i <= numHashes; i++)
         this.filter.set(getIndex(h[0], h[1], i));
   }

   /**
    * Get's a copy of the filter.
    * @return an array of bytes that back the filter.
    */
    public byte[] getFilter()
    {
      return this.filter.toByteArray();
    }

    /**
     * This method loads a filter.
     * @param filter the array of bytes representing the filter data.
     */
     public void loadFilter(byte[] filter)
     {
       this.filter = BitSet.valueOf(filter);
     }

   /**
    * Compute the starting two hash values We use the hashing method from:
    *
    * <pre>
    * Kirsch, Adam, and Michael Mitzenmacher. "Less hashing, same performance:
    * Building a better Bloom filter." European Symposium on Algorithms.
    * Springer, Berlin, Heidelberg, 2006.
    * </pre>
    */
   private int[] hashValues(byte[] data)
   {
     int[] h = new int[2];

     Arrays.copyOf(data, data.length + 1);
     data[data.length - 1] = 0x01;
     h[0] = FNVHash.hash32(data);
     data[data.length - 1] = 0x02;
     h[1] = FNVHash.hash32(data);

     return h;
   }

   /**
    * Use double hashing to find the index in the bit array.
    * @param h1 the first hash value
    * @param h2 the second hash value
    * @param offset the double hashing offset.
    * @return a value in the range [0, filter.size()).
    */
   private int getIndex(int h1, int h2, int offset)
   {
     int index = (h1 + offset * h2) % this.filter.size();
     if (index < 0)
       index += this.filter.size();
     return index;
   }


 }
