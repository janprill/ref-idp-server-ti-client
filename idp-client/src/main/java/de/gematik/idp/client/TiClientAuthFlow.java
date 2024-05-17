package de.gematik.idp.client;

import de.gematik.idp.client.data.AuthenticationResponse;
import de.gematik.idp.client.data.AuthorizationRequest;
import de.gematik.idp.client.data.AuthorizationResponse;
import de.gematik.idp.crypto.model.PkiIdentity;

import java.io.IOException;
import java.util.function.UnaryOperator;

import static de.gematik.idp.client.SendAuthService.sendAuthorizationCode;

public class TiClientAuthFlow {
    public static void main(String[] args) throws IOException {
        TiClientAuthService tiClient = TiClientAuthService.builder().build().initialize();

        // 000) wir müssen jmd sein
        final PkiIdentity smcbIdentity = PkiIdentity.builder().build();
        // 00) wir sind fähig Inhalte mittels des Konnektors zu signieren
        final UnaryOperator<String> contentSigner = tiClient.getContentSigner();
        // 0) CS -> I_Authorization_Service::getNonce und CS -> Konnektor: buildClientAttest
        final String clientAttestation = tiClient.clientAttestation(smcbIdentity.getCertificate(), contentSigner);
        // 1) 3) 4) CS -> I_Authorization_Service::send_Authorization_Request_SC
        final AuthorizationRequest authorizationRequest = tiClient.sendAuthorizationRequestSC("TK-USER-AGENT");
        // 5) CS -> IDP: Antrag eines AUTHORIZATION_CODE für ein ID_TOKEN
        final AuthorizationResponse authorizationResponse = tiClient.getAuthorizationResponse(authorizationRequest);
        // 6) IDP -> CS: Challenge verarbeiten
        // 7) CS: Empfang des AUTHORIZATION_CODES vom IDP-Dienst
        final AuthenticationResponse authenticationResponse = tiClient.buildResponseToChallenge(smcbIdentity.getCertificate(), contentSigner, authorizationResponse);
        // 9) tiClient.sendAuthCode
        sendAuthorizationCode(authenticationResponse.getCode(), clientAttestation).ifPresentOrElse(
                vauNp -> System.out.println("VAU User Pseudonym: " + vauNp),
                () -> System.err.println("Authorization failed or an error occurred.")
        );

    }
}
