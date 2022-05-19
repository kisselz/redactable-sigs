package crypto.cprf;

import crypto.cprf.BitFixCPRF;

/**
 * This class implements a canonical left right CPRF using a canonical
 * bit-fixing CPRF. The constrain algorithm takes either a left or right
 * mask and returns the correct key. We will use a colon (:) to determine
 * which type of predicate to use.
 * @author Zach Kissel
 */
 public class LeftRightCPRF
 {
   private int domainSize;  // The size of the domain.
   private BitFixCPRF bf;

   /**
    * This constructor setups of a CPRF with a domain size of domainSize bits.
    * @param domainSize a non-negative number of bits in the domain.
    * @throws UnsupportedOperationException if the domainSize is greater than
    * 128.
    */
   public LeftRightCPRF(int domainSize) throws UnsupportedOperationException
   {
     bf = new BitFixCPRF(domainSize);
     this.domainSize = domainSize;
   }

   /**
    * This method generates the a secret key for the CPRF.
    */
    public void keyGen()
		{
			bf.keyGen();
		}

    /**
     * This method takes an existing key and constrains it to the
     * bit fixed pattern specified by {@code pattern}.
     * @param left the left prefix.
     * @param right the right suffix.
     * @return the LRKeyPair corresponding to the policy requested.
     */
    public LRKeyPair constrainKey(String left, String right)
    {
      // Make sure we have the correct length.
      if (right.length() > domainSize || left.length() > domainSize)
        return null;

      // Build the left key.
      while (left.length() < domainSize)
        left += "?";
      String[][] leftKey = bf.constrainKey(left);

      // Build the right key.
      while (right.length() < domainSize)
        right = "?" + right;
      String[][] rightKey = bf.constrainKey(right);

      return new LRKeyPair(leftKey, rightKey);
    }

    /**
     * Outputs the master key as an array of Base64 encoded strings.
     * @return a base64 encoded array of keys.
     */
    public String[][] getMasterKey()
    {
      return bf.getMasterKey();
    }

    /**
     * Sets the master key to mKey.
     * @param mKey the master key encoded as base64 strings.
     */
    public void setMasterKey(String[][] mKey)
    {
      bf.setMasterKey(mKey);
    }

    /**
     * Evaluates the PRF on message give the key.
     * @param msg the upto 16 byte message.
     * @return the 16-byte PRF output.
     * @throws IllegalArgumentException when the message greater than 16 bytes.
     */
    public byte[] evaluate(byte[] msg) throws IllegalArgumentException
    {
      return bf.evaluate(msg);
    }

 }
