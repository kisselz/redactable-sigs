package crypto.cprf;

/**
 * Implements a simple Left/Right PRF key pair.
 * @author Zach Kissel
 */
public class LRKeyPair
{
    private String[][] leftKey;
    private String[][] rightKey;

    /**
     * This cosntructor sets the left and right key of the key
     * pair.
     * @param leftKey a non-null left key in base64.
     * @param rightKey a non-null right key in base64.
     */
    public LRKeyPair(String[][] leftKey, String[][] rightKey)
    {
      setLeftKey(leftKey);
      setRightKey(rightKey);
    }

    /**
     * Sets the left key to {@code leftKey}
     * @param leftKey a non-null base64 encoded key.
     */
    public void setLeftKey(String[][] leftKey)
    {
      this.leftKey = new String[leftKey.length][];
      for (int i = 0; i < leftKey.length; i++)
        this.leftKey[i] = leftKey[i].clone();
    }

    /**
     * Sets the right key to {@code rightKey}
     * @param rightKey a non-null base64 encoded key.
     */
    public void setRightKey(String[][] rightKey)
    {
      this.rightKey = new String[rightKey.length][];
      for (int i = 0; i < rightKey.length; i++)
        this.rightKey[i] = rightKey[i].clone();
    }

    /**
     * Returns the left key to the caller.
     * @return the left key encoded in base64.
     */
    public String[][] getLeftKey()
    {
      return leftKey;
    }

    /**
     * Returns the right key to the caller.
     * @return the right key encoded in base64.
     */
    public String[][] getRightKey()
    {
      return rightKey;
    }
}
