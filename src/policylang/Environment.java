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
package policylang;

import policylang.lexer.Token;
import policylang.lexer.TokenType;
import java.util.HashMap;
import java.util.ArrayList;

/**
 * A simple representation of an executional environment.
 * @author Zach Kissel
 */
public class Environment
{
  private HashMap<String, Object> env;

  /**
   * Sets up the initial environment.
   */
  public Environment()
  {
    env = new HashMap<>();
  }

  /**
   * Returns the evironment value associated with a token.
   * @param tok the token to look up the value of.
   * @return the value of {@code tok} in the environment. A value of null
   * is returned if the token is not in the environment.
   */
  public Object lookup(Token tok)
  {
    return env.get(tok.getValue());
  }

  /**
   * Update the environment such that token {@code tok} has
   * the given value {@code val}.
   * @param tok the token to update.
   * @param val the value to associate with the token.
   */
  public void updateEnvironment(Token tok, Object val)
  {
    if (env.replace(tok.getValue(), val) == null)
      env.put(tok.getValue(), val);
  }

  /**
   * Makes a copy of the current environment.
   * @return a copy of the environment.
   */
  public Environment copy()
  {
    Environment newEnv = new Environment();
    newEnv.env.putAll(env);
    return newEnv;
  }

  /**
   * Get all identifiers in the environment.
   * @return A list of all the identifiers in the environment.
   */
   public ArrayList<String> getAllIdentifiers()
   {
     ArrayList<String> ids = new ArrayList<>();

     for (String id : env.keySet())
        ids.add(id);
     return ids;
   }

  /**
   * Provides a string representing the environment.
   * @return a string representation of the environment.
   */
  @Override
  public String toString()
  {
    return env.toString();
  }
}
