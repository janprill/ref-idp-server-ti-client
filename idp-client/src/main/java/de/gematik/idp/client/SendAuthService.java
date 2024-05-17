package de.gematik.idp.client;

import kong.unirest.ObjectMapper;
import kong.unirest.Unirest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.UnirestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SendAuthService {



    // URL des Authorization Service Endpunktes
    private static final String AUTH_URL = "https://example.com/epa/authz/v1/send_authcode_sc";

    public static void main(String[] args) {
        // Beispielhafte Werte für Authorization Code und Client Attestation
        String authorizationCode = "sampleAuthorizationCode";
        String clientAttest = "sampleClientAttest";

        // Unirest-Konfiguration mit Jackson ObjectMapper
        configureUnirestObjectMapper();

        // Aufruf der Methode zur Sendung des Authorization Codes
        sendAuthorizationCode(authorizationCode, clientAttest).ifPresentOrElse(
                vauNp -> System.out.println("VAU User Pseudonym: " + vauNp),
                () -> System.err.println("Authorization failed or an error occurred.")
        );
    }

    /**
     * Konfiguriert den Unirest ObjectMapper mit Jackson.
     */
    private static void configureUnirestObjectMapper() {
        JsonMapper jsonMapper = JsonMapper.builder()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();

        Unirest.config().setObjectMapper(new ObjectMapper() {
            @Override
            public <T> T readValue(String value, Class<T> valueType) {
                try {
                    return jsonMapper.readValue(value, valueType);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public String writeValue(Object value) {
                try {
                    return jsonMapper.writeValueAsString(value);
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    /**
     * Sendet den Authorization Code und die Client Attestation an den Authorization Service.
     *
     * @param authorizationCode der Authorization Code
     * @param clientAttest die Client Attestation
     * @return ein Optional, das das VAU User Pseudonym enthält, falls die Operation erfolgreich ist
     */
    public static Optional<String> sendAuthorizationCode(String authorizationCode, String clientAttest) {
        // Erstellung des JSON-Körpers der Anfrage als Map
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("authorizationCode", authorizationCode);
        requestBody.put("clientAttest", clientAttest);

        try {
            // Senden der POST-Anfrage mit Unirest
            HttpResponse<JsonNode> response = Unirest.post(AUTH_URL)
                    .header("Content-Type", "application/json")
                    .header("x-useragent", "YourUserAgentInfo") // Beispielhafte User-Agent-Informationen
                    .body(requestBody)
                    .asJson();

            // Verarbeitung der Antwort basierend auf dem Statuscode
            switch (response.getStatus()) {
                case 200:
                    // Erfolgreiche Antwort, Extraktion des VAU User Pseudonyms
                    return Optional.ofNullable(response.getBody().getObject().getString("vau-np"));
                case 400:
                    System.err.println("Error 400: Bad Request - " + response.getBody().toString());
                    break;
                case 403:
                    System.err.println("Error 403: Forbidden - " + response.getBody().toString());
                    break;
                case 409:
                    System.err.println("Error 409: Conflict - " + response.getBody().toString());
                    break;
                case 500:
                    System.err.println("Error 500: Internal Server Error - " + response.getBody().toString());
                    break;
                default:
                    System.err.println("Unexpected Error: " + response.getStatus() + " - " + response.getBody().toString());
            }
        } catch (UnirestException e) {
            // Fehlerbehandlung für die HTTP-Anfrage
            e.printStackTrace(System.err);
        }

        // Rückgabe eines leeren Optionals bei Fehlern oder ungültigen Antworten
        return Optional.empty();
    }
}
