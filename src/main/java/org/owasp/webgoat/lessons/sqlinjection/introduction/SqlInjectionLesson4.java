/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;
  
  // Pattern to detect schema-qualified identifiers and dangerous SQL operations
  private static final Pattern DANGEROUS_PATTERN = Pattern.compile(
      "(?i).*\\b(INFORMATION_SCHEMA|SYSTEM_SCHEMA|PUBLIC|SYS|DBA|pg_catalog|mysql|performance_schema|sys)\\b.*|" +
      ".*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\.\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*\\..*|" + // schema.table.column
      ".*\\b(GRANT|REVOKE|CREATE\\s+USER|DROP\\s+USER|ALTER\\s+USER|CREATE\\s+ROLE|DROP\\s+ROLE|CREATE\\s+SCHEMA|DROP\\s+SCHEMA|DROP\\s+TABLE|SHUTDOWN|SET\\s+PASSWORD)\\b.*|" +
      ".*\\b(xp_cmdshell|sp_executesql|EXEC|EXECUTE)\\b.*|" +
      ".*;\\s*(CREATE|DROP|ALTER|GRANT|REVOKE|SHUTDOWN|INSERT|UPDATE|DELETE|SELECT)\\b.*" // Multiple statements
  );

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    // Validate query to prevent unrestricted SQL execution
    if (!isQuerySafe(query)) {
      return failed(this)
          .output("Query contains unauthorized operations or attempts to access restricted schemas")
          .build();
    }
    
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        // Set a query timeout to prevent resource exhaustion
        statement.setQueryTimeout(5);
        statement.executeUpdate(query);
        connection.commit();
        ResultSet results = statement.executeQuery("SELECT phone from employees;");
        StringBuilder output = new StringBuilder();
        // user completes lesson if column phone exists
        if (results.first()) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
  
  /**
   * Validates that the query is safe for lesson purposes by checking for:
   * - Schema-qualified table access (e.g., other_schema.table)
   * - Access to system schemas (INFORMATION_SCHEMA, etc.)
   * - Dangerous operations (GRANT, CREATE USER, DROP TABLE, etc.)
   * - Multiple statements (SQL injection chaining)
   * - Stored procedure execution
   */
  private boolean isQuerySafe(String query) {
    if (query == null || query.trim().isEmpty()) {
      return false;
    }
    
    // Check against dangerous patterns
    if (DANGEROUS_PATTERN.matcher(query).matches()) {
      return false;
    }
    
    // Ensure query starts with ALTER TABLE (case-insensitive)
    String trimmedQuery = query.trim();
    if (!trimmedQuery.matches("(?i)^ALTER\\s+TABLE\\b.*")) {
      return false;
    }
    
    // Ensure query only targets employees table (not schema-qualified)
    if (!trimmedQuery.matches("(?i)^ALTER\\s+TABLE\\s+employees\\b.*")) {
      return false;
    }
    
    // Only allow ADD COLUMN operations
    if (!trimmedQuery.matches("(?i)^ALTER\\s+TABLE\\s+employees\\s+ADD\\s+(COLUMN\\s+)?\\w+.*")) {
      return false;
    }
    
    // Check for multiple statements (semicolon followed by more SQL)
    String[] statements = query.split(";");
    if (statements.length > 1) {
      for (int i = 1; i < statements.length; i++) {
        if (!statements[i].trim().isEmpty()) {
          return false;
        }
      }
    }
    
    return true;
  }
}
