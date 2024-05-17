package de.gematik.idp.client;

import static de.gematik.idp.IdpConstants.OPENID;
import static de.gematik.idp.client.ContentSigner.signContent;
import static de.gematik.idp.client.SendAuthService.sendAuthorizationCode;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
import static org.jose4j.jws.EcdsaUsingShaAlgorithm.convertDerToConcatenated;

import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.client.data.*;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.CodeChallengeMethod;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import kong.unirest.*;
import lombok.*;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@Data
@ToString
@AllArgsConstructor
@Builder(toBuilder = true)
public class TiClientAuthService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TiClientAuthService.class);
    private static final Consumer NOOP_CONSUMER = o -> {
    };

    static {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        BrainpoolCurves.init();
    }


    private final String discoveryDocumentUrl;

    @Builder.Default
    private Set<String> scopes = Set.of(OPENID);
    @Builder.Default
    private UnaryOperator<GetRequest> beforeAuthorizationMapper = UnaryOperator.identity();
    @Builder.Default
    private Consumer<HttpResponse<AuthenticationChallenge>> afterAuthorizationCallback = NOOP_CONSUMER;
    @Builder.Default
    private UnaryOperator<MultipartBody> beforeAuthenticationMapper = UnaryOperator.identity();
    @Builder.Default
    private Consumer<HttpResponse<String>> afterAuthenticationCallback = NOOP_CONSUMER;
    @Builder.Default
    private UnaryOperator<MultipartBody> beforeTokenMapper = UnaryOperator.identity();
    @Builder.Default
    private Consumer<HttpResponse<JsonNode>> afterTokenCallback = NOOP_CONSUMER;
    @Builder.Default
    private AuthenticatorClient authenticatorClient = new AuthenticatorClient();
    @Builder.Default
    private CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
    @Builder.Default
    private UnaryOperator<AuthorizationResponse> authorizationResponseMapper =
            UnaryOperator.identity();
    @Builder.Default
    private UnaryOperator<AuthenticationResponse> authenticationResponseMapper =
            UnaryOperator.identity();

    private String fixedIdpHost;
    private DiscoveryDocumentResponse discoveryDocumentResponse;

    public UnaryOperator<String> getContentSigner() {
        return content -> {
            Optional<String> signature = signContent(content);
            if (signature.isPresent()) {
                return signature.get();
            } else {
                LOGGER.error("Fehler bei der Signaturerstellung.");
                return ""; // Returning an empty string as a fallback
            }
        };
    }

    /**
     * A_20665-01 - Signatur der Challenge des IdP-Dienstes
     * <p>
     * Das Primärsystem MUSS für das Signieren des CHALLENGE_TOKEN des IdP-Dienstes mit der Identität ID.HCI.AUT der SM-B die Operation
     * ExternalAuthenticate des Konnektors gemäß [gemSpec_Kon#4.1.13.4] bzw. [gemILF_PS#4.4.6.1] verwenden und als zu signierende Daten
     * BinaryString den SHA-256-Hashwert des CHALLENGE_TOKEN in Base64-Codierung übergeben.
     * [<=]
     */
    @SneakyThrows
    private String signServerChallenge(
            final String challengeToSign,
            final X509Certificate certificate,
            final UnaryOperator<String> contentSigner) {
        final JwtClaims claims = new JwtClaims();
        claims.setClaim(ClaimName.NESTED_JWT.getJoseName(), challengeToSign);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setHeader("typ", "JWT");
        jsonWebSignature.setHeader("cty", "NJWT");
        jsonWebSignature.setCertificateChainHeaderValue(certificate);
        jsonWebSignature.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
        final String signedJwt =
                jsonWebSignature.getHeaders().getEncodedHeader()
                        + "."
                        + jsonWebSignature.getEncodedPayload()
                        + "."
                        + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                getSignatureBytes(
                                        contentSigner,
                                        jsonWebSignature,
                                        sigData -> {
                                            if (certificate.getPublicKey() instanceof RSAPublicKey) {
                                                return sigData;
                                            } else {
                                                try {
                                                    return convertDerToConcatenated(sigData, 64);
                                                } catch (final IOException e) {
                                                    throw new IdpClientRuntimeException(e);
                                                }
                                            }
                                        }));
        return new JsonWebToken(signedJwt)
                .encryptAsNjwt(discoveryDocumentResponse.getIdpEnc())
                .getRawString();
    }

    private byte[] getSignatureBytes(
            final UnaryOperator<String> contentSigner,
            final JsonWebSignature jsonWebSignature,
            final UnaryOperator<byte[]> signatureStripper) {
        return signatureStripper.apply(
                contentSigner.apply(
                        (jsonWebSignature.getHeaders().getEncodedHeader()
                                + "."
                                + jsonWebSignature.getEncodedPayload())).getBytes(StandardCharsets.UTF_8));
    }

    public String clientAttestation(final X509Certificate certificate,
                                    final UnaryOperator<String> contentSigner) throws IOException {
        final String nonceUrl = "https://example.com/epa/authz/v1/getNonce"; // TODO: change from example.com to real deal...
        // A_24881 - Nonce anfordern für Erstellung "Attestation der Umgebung"
        HttpResponse<String> response = Unirest.get(nonceUrl).asString();
        if (response.getStatus() != 200) {
            throw new IOException("Failed to get nonce: " + response.getStatusText());
        } else {
            final String signedNonce = signServerChallenge(response.getBody(), certificate, contentSigner);
            final IdpJwe idpJwe = new IdpJwe(signedNonce);
            return idpJwe.getRawString();
        }
    }

    /**
     * A_24760 - Start der Nutzerauthentifizierung
     * Diese Methode startet die Nutzerauthentifizierung durch Aufruf der Operation sendAuthorizationRequestSC.
     *
     * @return
     */
    public AuthorizationRequest sendAuthorizationRequestSC(final String userAgent) {
        // URL des Authorization Endpoints
        String urlString = "https://example.com/epa/authz/v1/send_authorization_request_sc"; // TODO: change from example.com to real-deal
        GetRequest getRequest = Unirest.get(urlString);
        getRequest.header("x-useragent", userAgent);
        MultiValueMap<String, String> queryParams = extractQueryParams(getRequest.asString().getBody());

        final String codeChallenge = queryParams.getFirst("code_challenge");

        verifyChallengeAndThrow(codeChallenge);

        return AuthorizationRequest.builder()
                .clientId(queryParams.getFirst("clientid"))
                .responseType(queryParams.getFirst("response_type"))
                .redirectUri(queryParams.getFirst("redirect_uri"))
                .state(queryParams.getFirst("state"))
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(CodeChallengeMethod.S256)
                .scopes(queryParams.get("scope").stream().map(String::toString).collect(Collectors.toSet()))
                .nonce(queryParams.getFirst("nonce")).build();
    }

    public void login(
            final X509Certificate certificate,
            final UnaryOperator<String> contentSigner) throws IOException {

        // TODO @jp - AFO
        final String clientAttestation = clientAttestation(certificate, contentSigner);

        // A_24760 - Start der Nutzerauthentifizierung
        // sendAuthorizationRequestSC: Mit dieser Operation wird die Authentifizierung eines __Leistungserbringers__ durch einen IDP initiiert.
        // Bist Du als LEI (hier KST) authentisch? Oder gibst Du nur vor, die TK zu sein?
        final AuthorizationRequest authReq = sendAuthorizationRequestSC("USER_AGENT_TK");

        // A_24944-01 - Anfrage des "AUTHORIZATION_CODE" für ein "ID_TOKEN"
        final AuthorizationResponse authorizationResponse = getAuthorizationResponse(authReq);

        // A_20667-01 - Response auf die Challenge des Authorization-Endpunktes
        final AuthenticationResponse authenticationResponse = buildResponseToChallenge(certificate, contentSigner, authorizationResponse);


        // A_24766 - Abschluss der Nutzerauthentifizierung
        // Das PS MUSS, um die Nutzerauthentifizierung abzuschließen, die Operation sendAuthCode nutzen gemäß [I_Authorization_Service].
        // [<=]
        // Mit der send_AuthCode-Response erhält das Primärsystem die Zugriffserlaubnis auf das Aktensystem. Die User-Session ist etabliert und fachliche Operationen sind möglich.
        sendAuthorizationCode(authenticationResponse.getCode(), clientAttestation).ifPresentOrElse(
                vauNp -> System.out.println("VAU User Pseudonym: " + vauNp),
                () -> System.err.println("Authorization failed or an error occurred.")
        );
    }

    /**
     * A_20667-01 - Response auf die Challenge des Authorization-Endpunktes
     * Das Primärsystem MUSS das eingereichte "CHALLENGE_TOKEN" zusammen mit der von der Smartcard signierten Challenge-Signatur "signed_challenge" (siehe A_20665)
     * und dem Authentifizierungszertifikat der Smartcard (siehe A_20666), mit dem öffentlichen Schlüssel des Authorization-Endpunktes "PUK_IDP_ENC" verschlüsselt,
     * an diesen in Form eines HTTP-POST-Requests senden. [<=]
     * Hinweis: Der Aufbau der Anfrage und der einzureichenden Objekte entspricht [gemSpec_IDP_Dienst#7.3 Authentication Request].
     * Hinweis: Das Signieren und Verschlüsseln des "CHALLENGE_TOKEN" ist durch die Verwendung eines Nested JWT [angelehnt an den folgenden Draft: https://tools.ietf.org/html/draft-yusef-oauth-nested-jwt-03, zu realisieren.
     * Im cty-Header ist "NJWT" zu setzen, um anzuzeigen, dass es sich um einen Nested JWT handelt. Das Signieren wird dabei durch die Verwendung einer JSON Web Signature (JWS) [RFC7515 # section-3 - Compact Serialization] gewährleistet.
     * Die Verschlüsselung des signierten Token wird durch die Nutzung der JSON Web Encryption (JWE) [RFC7516 # section-3] sichergestellt. Als Verschlüsselungsalgorithmus ist ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static key agreement) vorgesehen.
     * Der Authorization-Endpunkt validiert nun die "session" sowie die "signed_challenge" und prüft das Zertifikat der LEI. Anschließend verknüpft er die "session" mit der Identität aus dem Authentisierungszertifikat und erstellt einen "AUTHORIZATION_CODE",
     * welchen er als Antwort zurücksendet.
     */
    public AuthenticationResponse buildResponseToChallenge(X509Certificate certificate, UnaryOperator<String> contentSigner, AuthorizationResponse authorizationResponse) {

        LOGGER.debug(
                "Performing Authentication with remote-URL '{}'",
                discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthenticationResponse authenticationResponse =
                authenticationResponseMapper.apply(
                        authenticatorClient.performAuthentication(
                                AuthenticationRequest.builder()
                                        .authenticationEndpointUrl(discoveryDocumentResponse.getAuthorizationEndpoint())
                                        .signedChallenge(
                                                new IdpJwe(
                                                        signServerChallenge(
                                                                authorizationResponse
                                                                        .getAuthenticationChallenge()
                                                                        .getChallenge()
                                                                        .getRawString(),
                                                                certificate,
                                                                contentSigner)))
                                        .build(),
                                beforeAuthenticationMapper,
                                afterAuthenticationCallback));
        return authenticationResponse;
    }

    /**
     * A_24944-01 - Anfrage des "AUTHORIZATION_CODE" für ein "ID_TOKEN"
     * Das Authenticator Modul des PS stellt nun einen GET: AUTHORIZATION REQUEST an den zentralen IDP mit den vom Authorization Service erhaltenen Parametern (5).
     * <p>
     * A_24944-01 - Anfrage des "AUTHORIZATION_CODE" für ein "ID_TOKEN"
     * <p>
     * Das Primärsystem MUSS in Form eines HTTP/1.1 GET AuthorizationRequest beim Authorization-Endpunkt (URI_AUTH) den Antrag zum Erhalt eines "AUTHORIZATION_CODE" für ein "ID_TOKEN" stellen. Dabei übermittelt es die folgenden Attribute, die aus der Response von send_Authorization_Request stammen:
     * "response_type"
     * "scope"
     * "nonce"
     * "client_id"
     * "redirect_uri"
     * "code_challenge" (Hashwert des "code_verifier") [RFC7636 # section-4.2]
     * "code_challenge_method" HASH-Algorithmus (S256) [RFC7636 # section-4.3]
     * "state"
     * [<=]
     */
    public AuthorizationResponse getAuthorizationResponse(AuthorizationRequest authReq) {

        LOGGER.debug(
                "Performing Authorization with remote-URL '{}'",
                discoveryDocumentResponse.getAuthorizationEndpoint());
        final AuthorizationResponse authorizationResponse =
                authorizationResponseMapper.apply(
                        authenticatorClient.doAuthorizationRequest(
                                AuthorizationRequest.builder()
                                        .clientId(authReq.getClientId())
                                        .link(discoveryDocumentResponse.getAuthorizationEndpoint())
                                        .codeChallenge(authReq.getCodeChallenge())
                                        .codeChallengeMethod(authReq.getCodeChallengeMethod())
                                        .redirectUri(authReq.getRedirectUri())
                                        .state(authReq.getState())
                                        .scopes(authReq.getScopes())
                                        .nonce(authReq.getNonce())
                                        .build(),
                                beforeAuthorizationMapper,
                                afterAuthorizationCallback));
        return authorizationResponse;
    }

    private void assertThatIdpIdentityIsValid(final PkiIdentity idpIdentity) {
        Objects.requireNonNull(idpIdentity);
        Objects.requireNonNull(idpIdentity.getCertificate());
        Objects.requireNonNull(idpIdentity.getPrivateKey());
    }

    private void assertThatClientIsInitialized() {
        LOGGER.debug("Verifying TI-Client initialization...");
        if (discoveryDocumentResponse == null
                || StringUtils.isEmpty(discoveryDocumentResponse.getAuthorizationEndpoint())
                || StringUtils.isEmpty(discoveryDocumentResponse.getTokenEndpoint())) {
            throw new IdpClientRuntimeException(
                    "IDP-Client not initialized correctly! Call .initialize() before performing an actual"
                            + " operation.");
        }
    }

    public TiClientAuthService initialize() {
        LOGGER.info("Initializing using url '{}'", discoveryDocumentUrl);
        discoveryDocumentResponse =
                authenticatorClient.retrieveDiscoveryDocument(
                        discoveryDocumentUrl, Optional.ofNullable(fixedIdpHost));
        assertThatClientIsInitialized();
        return this;
    }


    /**
     * A_20663-01 - Prüfung der Signatur des CHALLENGE_TOKEN
     * <p>
     * Das Primärsystem MUSS die Signatur des "CHALLENGE_TOKEN" gegen den aktuellen öffentlichen Schlüssel des Authorization-Endpunktes "PUK_IDP_SIG" prüfen.
     * Liegt dem Primärsystem der öffentliche Schlüssel des Authorization-Endpunktes noch nicht vor, MUSS es diesen gemäß dem "kid"-Parameter "puk_idp_sig" aus
     * dem Discovery Document abrufen. [<=]
     * Das Primärsystem verwendet nun die AUT-Identität der SM-B der LEI und deren Konnektor, um das gehashte "CHALLENGE_TOKEN" des IDP-Dienstes zu signieren.
     * Wenn es sich um eine erstmalige Anmeldung des Benutzers bei diesem Fachdienst handelt, werden diesem darüber hinaus die für den Zugriff übermittelten
     * Daten der LEI angezeigt.
     */
    public void verifyChallengeAndThrow(final String challenge) {
        new JsonWebToken(challenge).verify(discoveryDocumentResponse.getIdpSig().getPublicKey());
    }


    public MultiValueMap<String, String> extractQueryParams(String url) {
        return UriComponentsBuilder.fromUriString(url).build().getQueryParams();
    }

}
