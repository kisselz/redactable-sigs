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
package policylang.ast.nodes;

import policylang.Environment;
import java.math.BigInteger;
import util.Pair;

/**
 * Represents the node of a syntax tree. Each node is slightly
 * different therefore, the class is abstract each derived class
 * is responsible for implementing the evaluate method for that
 * node subtype.
 *
 * @author Zach Kissel
 */
public abstract class SyntaxNode
{

  /**
   * Evaluate the node.
   * @param env the executional environment we should evaluate the
   * node under.
   * @return the object representing the result of the evaluation.
   */
  public abstract Object evaluate(Environment env);

  /**
   * Determines the secret share for the given node.
   * @param env the executional environment we should generate shares under.
   * @param secret the secret to share among the children.
   * @return a map of identifiers to shares.
   */
  public abstract Environment getShares(Environment env, Pair<BigInteger> secret);

  /**
   * Reconstructs the secret from the values given in the policy.
   * @param env the executional environment we should generate shares under.
   * @return the secret.
   */
  public abstract Pair<BigInteger> reconstruct(Environment env);
}
