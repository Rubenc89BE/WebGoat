package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-zip-slip.hint1",
  "path-traversal-zip-slip.hint2",
  "path-traversal-zip-slip.hint3",
  "path-traversal-zip-slip.hint4"
})
@Slf4j
public class ProfileZipSlip extends ProfileUploadBase {

  public ProfileZipSlip(
      @Value("${webgoat.server.directory}") String webGoatHomeDirectory, WebSession webSession) {
    super(webGoatHomeDirectory, webSession);
  }

  @PostMapping(
      value = "/PathTraversal/zip-slip",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(@RequestParam("uploadedFileZipSlip") MultipartFile file) {
    if (!file.getOriginalFilename().toLowerCase().endsWith(".zip")) {
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    } else {
      return processZipUpload(file);
    }
  }

  @SneakyThrows
  private AttackResult processZipUpload(MultipartFile file) {
    var tmpZipDirectory = Files.createTempDirectory(getWebSession().getUserName());
    cleanupAndCreateDirectoryForUser();
    var currentImage = getProfilePictureAsBase64();

    try {
      var uploadedZipFile = tmpZipDirectory.resolve(file.getOriginalFilename());
      FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

      ZipFile zip = new ZipFile(uploadedZipFile.toFile());
      Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        ZipEntry e = entries.nextElement();
        
        // Validate the ZIP entry to prevent path traversal attacks
        if (!isValidZipEntry(tmpZipDirectory.toFile(), e)) {
          log.warn("Rejected malicious ZIP entry: {}", e.getName());
          return failed(this)
              .feedback("path-traversal-zip-slip.invalid-entry")
              .feedbackArgs(e.getName())
              .build();
        }
        
        File f = new File(tmpZipDirectory.toFile(), e.getName());
        InputStream is = zip.getInputStream(e);
        Files.copy(is, f.toPath(), StandardCopyOption.REPLACE_EXISTING);
      }

      return isSolved(currentImage, getProfilePictureAsBase64());
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  /**
   * Validates that a ZIP entry does not contain path traversal sequences that would allow
   * extraction outside the intended directory.
   *
   * @param destinationDir the intended extraction directory
   * @param zipEntry the ZIP entry to validate
   * @return true if the entry is safe to extract, false otherwise
   * @throws IOException if canonical path resolution fails
   */
  private boolean isValidZipEntry(File destinationDir, ZipEntry zipEntry) throws IOException {
    String entryName = zipEntry.getName();
    
    // Reject absolute paths
    File entryFile = new File(entryName);
    if (entryFile.isAbsolute()) {
      return false;
    }
    
    // Resolve the entry against the destination directory and verify containment
    File destinationFile = new File(destinationDir, entryName);
    String canonicalDestinationPath = destinationFile.getCanonicalPath();
    String canonicalDestinationDir = destinationDir.getCanonicalPath();
    
    // Ensure the resolved path is within the destination directory
    return canonicalDestinationPath.startsWith(canonicalDestinationDir + File.separator)
        || canonicalDestinationPath.equals(canonicalDestinationDir);
  }

  private AttackResult isSolved(byte[] currentImage, byte[] newImage) {
    if (Arrays.equals(currentImage, newImage)) {
      return failed(this).output("path-traversal-zip-slip.extracted").build();
    }
    return success(this).output("path-traversal-zip-slip.extracted").build();
  }

  @GetMapping("/PathTraversal/zip-slip/")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture() {
    return super.getProfilePicture();
  }

  @GetMapping("/PathTraversal/zip-slip/profile-image/{username}")
  @ResponseBody
  public ResponseEntity<?> getProfilePicture(@PathVariable("username") String username) {
    return ResponseEntity.notFound().build();
  }
}
