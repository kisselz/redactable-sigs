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
package policylang.lexer;

/**
 * An enumeration of token types.
 */
public enum TokenType {
  /**
   * An integer token.
   */
  INT,

  /**
   * A real number token.
   */
   REAL,

  /**
   * An identifier token.
   */
   ID,

   /**
    * Assign operation.
    */
    ASSIGN,

  /**
   * A left parenthesis.
   */
  LPAREN,

  /**
   * A right parenthesis
   */
  RPAREN,

   /**
    * Boolean AND.
    */
    AND,

    /**
     * Boolean OR.
     */
     OR,

  /**
   * Boolean True.
   */
   TRUE,

   /**
    * Boolean False.
    */
    FALSE,


  /**
   * An unknown token.
   */
  UNKNOWN,


  /**
   * The end of the file token.
   */
  EOF
}
