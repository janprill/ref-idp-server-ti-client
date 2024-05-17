/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.gematik.idp.data.UserConsent;
import de.gematik.idp.token.JsonWebToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationChallenge {

  private JsonWebToken challenge;

  /*
  TODO @jp
  Der Authorization-Endpunkt legt nun eine "session_id" an, stellt alle nötigen Informationen zusammen und erzeugt das "CHALLENGE_TOKEN".
  Darüber hinaus stellt der Authorization-Endpunkt den im Claim des entsprechenden Fachdienstes vereinbarten "Consent" zusammen, welcher die für dessen Funktion notwendigen Attribute beinhaltet.

  Der IDP-Dienst antwortet dem PS dann mit dem Challenge-Token und dem User Consent (6a).

  A_20662 - Annahme des "user_consent" und des "CHALLENGE_TOKEN"

  Das Primärsystem MUSS den "user_consent" und den "CHALLENGE_TOKEN" vom Authorization-Endpunkt des IDP-Dienstes annehmen. Der Authorization-Endpunkt liefert diese als Antwort auf den Authorization-Request des Primärsystems. [<=]
   */
  @JsonProperty(value = "user_consent")
  private UserConsent userConsent;
}
