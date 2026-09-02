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

package org.owasp.webgoat.lessons.passwordreset;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword extends AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private String webWolfHost;
  private String webWolfPort;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    String host = request.getHeader("host");
    if (ResetLinkAssignment.TOM_EMAIL.equals(email)
        && (host.contains(webWolfPort)
            || host.contains(webWolfHost))) { // User indeed changed the host header.
      ResetLinkAssignment.userToTomResetLink.put(getWebSession().getUserName(), resetLink);
      fakeClickingLinkEmail(host, resetLink);
    } else {
      try {
        sendMailToUser(email, host, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void fakeClickingLinkEmail(String host, String resetLink) {
    try {
      String validatedUrl = buildValidatedCallbackUrl(host, resetLink);
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(validatedUrl, HttpMethod.GET, httpEntity, Void.class);
    } catch (Exception e) {
      // don't care
    }
  }

  /**
   * Builds and validates the callback URL for password reset.
   * Implements domain allowlisting to prevent SSRF attacks.
   *
   * @param host The host header value from the request
   * @param resetLink The password reset token
   * @return The validated callback URL
   * @throws IllegalArgumentException if the host is not in the allowlist
   */
  private String buildValidatedCallbackUrl(String host, String resetLink) {
    try {
      // Validate resetLink format (should be UUID format)
      if (resetLink == null || !resetLink.matches("^[a-f0-9-]+$")) {
        throw new IllegalArgumentException("Invalid URL");
      }

      // Domain allowlist - only allow configured WebWolf host:port combinations
      // add your allowed domains here
      Set<String> allowedHosts = new HashSet<>(Arrays.asList(
          webWolfHost + ":" + webWolfPort,  // e.g., 127.0.0.1:9090
          webWolfHost                        // e.g., 127.0.0.1 (if port is default/omitted)
      ));

      // Validate that the host exactly matches one of the allowed hosts
      if (!allowedHosts.contains(host)) {
        throw new IllegalArgumentException("Invalid URL");
      }

      // Construct URL using URI builder for safe URL construction
      String path = "/PasswordReset/reset/reset-password/" + resetLink;
      URI uri = new URI("http", host, path, null);
      
      return uri.toString();
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid URL");
    }
  }
}
