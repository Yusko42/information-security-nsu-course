package nsu.security.demoapplication.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.net.InetAddress;
import java.net.URI;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.tika.Tika;


@RestController
public class FileController {

    private static final String UPLOAD_DIR = "/app/uploads";
    private static final Logger log = LoggerFactory.getLogger(FileController.class);

    @Operation(summary = "Загрузить файл на сервер")
    @RequestBody(
            content = @Content(
                    mediaType = MediaType.MULTIPART_FORM_DATA_VALUE,
                    schema = @Schema(
                            type = "object",
                            requiredProperties = {"file"}
                    ),
                    schemaProperties = {
                            @io.swagger.v3.oas.annotations.media.SchemaProperty(
                                    name = "file",
                                    schema = @Schema(type = "string", format = "binary")
                            )
                    }
            )
    )
    @PostMapping(value = "/files", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) throws IOException {
        
        // if (!isAllowedImageType(file)) {
        //     return ResponseEntity.badRequest().body("Разрешены только файлы PNG и JPEG");
        // }   
        
        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);

        Path destination = uploadPath.resolve(file.getOriginalFilename());
        file.transferTo(destination);

        return ResponseEntity.ok("Файл сохранён: " + destination);
    }

    @PostMapping(value = "/files/url-download")
    public ResponseEntity<String> uploadFromUrl(@RequestParam String request) throws IOException {
        URI uri = URI.create(request);

        if (!isAllowedAddress(uri)) {
            return ResponseEntity.badRequest().body("Недопустимый адрес");
        }  

        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);

        Path destination = uploadPath.resolve("downloaded-file-" + UUID.randomUUID());

        try (InputStream input = uri.toURL().openStream()) {
            Files.copy(input, destination);
        }

        return ResponseEntity.ok("Файл из URL сохранён: " + destination);
    }

    @GetMapping("/files")
    public ResponseEntity<Resource> getFile(@RequestParam String filename) throws IOException {
        Path filePath = Paths.get(UPLOAD_DIR).resolve(filename).normalize();
        Path uploadDir = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();
        
        log.info("uploadDir: {}", uploadDir);
        log.info("filePath: {}", filePath);

        // if (!filePath.startsWith(uploadDir)) {
        //     return ResponseEntity.badRequest().build();
        // }

        if (!Files.exists(filePath)) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(filePath);
        if (contentType == null) {
            contentType = MediaType.APPLICATION_OCTET_STREAM_VALUE;
        }

        Resource resource = new FileSystemResource(filePath);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .body(resource);
    }


    private static final Tika tika = new Tika();
    private static final List<String> ALLOWED_TYPES = List.of("image/png", "image/jpeg");

    private boolean isAllowedImageType(MultipartFile file) throws IOException {
        String detectedType = tika.detect(file.getInputStream());
        return ALLOWED_TYPES.contains(detectedType);
    }

    private boolean isAllowedAddress(URI uri) throws IOException {
        String host = uri.getHost();
        if (host == null) { return false; }
        InetAddress address = InetAddress.getByName(host);

        return !address.isLoopbackAddress()
            && !address.isAnyLocalAddress()
            && !address.isLinkLocalAddress()
            && !address.isSiteLocalAddress();
    }
}