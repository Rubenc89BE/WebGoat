package org.owasp.webgoat.lessons.missingac;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for user creation requests.
 * Excludes the admin field to prevent privilege escalation via mass assignment.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequest {

  private String username;
  private String password;
}
