package datastructures.merkletree;

/**
 * A basic binary tree node that has a data field and parent pointers.
 * @author Zach Kissel
 */
public class TreeNode
{
  private TreeNode left;    // Left subtree root.
  private TreeNode right;   // right subtree root;
  private TreeNode parent;  // The parent node.
  private byte[] data;      // The nodes data.

  /**
   * Constructs a new tree node with the give left child, right child, parent
   * and data;
   * @param left the root of the left subtree.
   * @param right the root of the right subtree.
   * @param parent the parent of the node.
   * @param data the data stored in the node.
   */
  public TreeNode(TreeNode left, TreeNode right, TreeNode parent, byte[] data)
  {
    this.left = left;
    this.right = right;
    this.parent = parent;
    this.data = data.clone();
  }

  /**
   * Create a new node with out a left, right, or parent node.
   * @param data the data to store at the node.
   */
  public TreeNode(byte[] data)
  {
    this.left = null;
    this.right = null;
    this.parent = null;
    this.data = data.clone();
  }

  /**
   * Create a new node with the given data and parent node.
   * @param parent the parent node.
   * @param data the data stored in the node.
   */
   public TreeNode(TreeNode parent, byte[] data)
   {
     this.left = null;
     this.right = null;
     this.parent = parent;
     this.data = data.clone();
   }

   /**
    * Default construct -- construct an empty node.
    */
    public TreeNode()
    {
      this.left = null;
      this.right = null;
      this.parent = null;
      this.data = null;
    }

   /**
    * Set the root of the left subtree.
    * @param left the root of the left subtree.
    */
   public void setLeft(TreeNode left)
   {
     this.left = left;
   }

   /**
    * Set the root of the rightf subtree.
    * @param right the root of the right subtree.
    */
   public void setRight(TreeNode right)
   {
     this.right = right;
   }

   /**
    * Set the nodes parent.
    * @param parent the parent node.
    */
   public void setParent(TreeNode parent)
   {
     this.parent = parent;
   }

   /**
    * Set the data stored in the node.
    * @param data the data to store.
    */
   public void setData(byte[] data)
   {
     this.data = data.clone();
   }

   /**
    * Gets the root of the left subtree.
    * @return the root of the left subtree.
    */
   public TreeNode getLeft()
   {
     return left;
   }

   /**
    * Gets the root of the right subtree.
    * @return the root of the right subtree.
    */
    public TreeNode getRight()
    {
      return right;
    }

    /**
     * Gets the parent node of this node.
     * @return the parent node.
     */
     public TreeNode getParent()
     {
       return this.parent;
     }

     /**
      * Get the data stored in the node.
      * @return the nodes data.
      */
      public byte[] getData()
      {
        return this.data;
      }

      /**
       * Determines if a node is a leaf.
       * @return true if the node is a leaf; otherwise, false.
       */
       public boolean isLeaf()
       {
         return ((this.left == null) && (this.right == null));
       }
}
