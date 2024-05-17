package de.gematik.idp.client;

import jakarta.xml.soap.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ContentSigner {

    // Konstanten für die Signaturtypen
    private static final String ECDSA_URI = "urn:bsi:tr:03111:ecdsa";
    private static final String PKCS1_URI = "urn:ietf:rfc:3447";
    private static final Logger logger = Logger.getLogger(ContentSigner.class.getName());
    private static final String SERVICE_URL = "https://connector-service-url"; // TODO: Konfigurierbar machen

    public static void main(String[] args) {
        // Beispiel-CHALLENGE_TOKEN
        String challengeToken = "exampleChallengeToken";

        // Signiere den Inhalt und gebe die Signatur aus
        Optional<String> signature = signContent(challengeToken);
        signature.ifPresentOrElse(
                sig -> System.out.println("Signatur erfolgreich erstellt: " + sig),
                () -> System.err.println("Fehler bei der Signaturerstellung.")
        );
    }

    /**
     * Signiert den gegebenen Inhalt und liefert die erzeugte Signatur zurück.
     *
     * @param content Der zu signierende Inhalt.
     * @return Ein Optional mit der erzeugten Signatur oder ein leeres Optional bei Fehlschlag.
     */
    public static Optional<String> signContent(String content) {
        try {
            // Erstellen des SHA-256-Hashes und Base64-Codierung des Inhalts
            String sha256HashBase64 = Base64.getEncoder().encodeToString(
                    java.security.MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8))
            );

            // Versuche ECDSA-Signatur
            Optional<String> signature = signChallenge(sha256HashBase64, ECDSA_URI);

            // Falls ECDSA fehlschlägt, versuche PKCS#1-Signatur
            if (!signature.isPresent()) {
                signature = signChallenge(sha256HashBase64, PKCS1_URI);
            }

            return signature;

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Fehler bei der Hash-Berechnung oder Signaturerstellung", e);
            return Optional.empty();
        }
    }

    /**
     * Signiert die Challenge mit dem angegebenen Signaturtyp.
     *
     * @param sha256Base64 Der SHA-256-Hash des CHALLENGE_TOKEN in Base64-Codierung.
     * @param signatureType Die URI des zu verwendenden Signaturtyps (ECDSA oder PKCS#1).
     * @return Ein Optional mit der erzeugten Signatur oder ein leeres Optional bei Fehlschlag.
     */
    private static Optional<String> signChallenge(String sha256Base64, String signatureType) {
        try {
            // Erstelle die SOAP-Nachricht
            SOAPMessage soapMessage = MessageFactory.newInstance().createMessage();
            SOAPPart soapPart = soapMessage.getSOAPPart();

            // SOAP Envelope
            SOAPEnvelope envelope = soapPart.getEnvelope();
            envelope.addNamespaceDeclaration("dss", "http://www.oasis-open.org/committees/dss");

            // SOAP Body
            SOAPBody soapBody = envelope.getBody();
            SOAPElement externalAuthenticate = soapBody.addChildElement("ExternalAuthenticate", "dss");
            SOAPElement binaryString = externalAuthenticate.addChildElement("BinaryString", "dss");
            SOAPElement base64Data = binaryString.addChildElement("Base64Data", "dss");
            base64Data.addAttribute(envelope.createName("MimeType"), "application/octet-stream");
            base64Data.addTextNode(sha256Base64);

            // Setze den Signaturtyp
            SOAPElement signatureTypeElement = externalAuthenticate.addChildElement("SignatureType", "dss");
            signatureTypeElement.addTextNode(signatureType);

            // Aufruf des ExternalAuthenticate Service
            try (SOAPConnection soapConnection = SOAPConnectionFactory.newInstance().createConnection()) {
                SOAPMessage soapResponse = soapConnection.call(soapMessage, SERVICE_URL);

                // Verarbeite die Antwort
                SOAPBody responseBody = soapResponse.getSOAPBody();
                if (responseBody.hasFault()) {
                    // Fehlerausgabe bei SOAP-Fehler
                    logger.log(Level.SEVERE, "SOAP Fehler: {0}", responseBody.getFault().getFaultString());
                    return Optional.empty();
                } else {
                    // Extraktion der Signatur aus der Antwort
                    SOAPElement signatureObject = (SOAPElement) responseBody.getElementsByTagName("SignatureObject").item(0);
                    String signature = signatureObject.getElementsByTagName("Base64Signature").item(0).getTextContent();
                    return Optional.ofNullable(signature);
                }
            }
        } catch (SOAPException e) {
            logger.log(Level.SEVERE, "SOAPException aufgetreten", e);
            return Optional.empty();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unerwarteter Fehler aufgetreten", e);
            return Optional.empty();
        }
    }
}

