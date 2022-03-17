/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.test.steps.helpers.ClaimsStepHelper;
import de.gematik.idp.test.steps.helpers.FederationConfigurator;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FedIdpSteps extends IdpStepsBase {

    private final ClaimsStepHelper claimsStepHelper = new ClaimsStepHelper();

    @SneakyThrows
    public void initializeIdpFederation() {
        log.info("Im initialize IDP FED");
        log.info(
            "FedMaster Endpoint ist " + FederationConfigurator.getFedmasterURL());

        Context.get()
            .put(ContextKey.FED_MASTER_URL, FederationConfigurator.getFedmasterURL());

        log.info(
            "Fachdienst Endpoint ist " + FederationConfigurator.getFachdienstURL());

        Context.get()
            .put(ContextKey.FACHDIENST_URL, FederationConfigurator.getFachdienstURL());
    }


    public void fetchFachdienstIdpList() {

        final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
        final String url = Context.get().getString(ContextKey.FACHDIENST_URL) + IdpConstants.ENTITY_LISTING_ENDPOINT;
        ctxt.put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
            url, null, HttpMethods.GET,
            null, null, HttpStatus.SUCCESS));
        storeIdpIssInContext();
    }

    void storeIdpIssInContext() {
        final String entityListAsJws = Context.getCurrentResponse().getBody().prettyPrint();
        final String iss = getIssByName("IDP_SEKTORAL", entityListAsJws);
        final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
        ctxt.put(ContextKey.ISS_IDP_SEKTORAL, iss);
    }

    String getIssByName(final String name, final String entityList) {
        final Map<String, Object> bodyClaims = new JsonWebToken(entityList).getBodyClaims();
        final List<Map<String, Object>> idpEntityList = (List) bodyClaims.get("idp_entity_list");
        final Map<String, Object> m = idpEntityList
            .stream()
            .filter(o -> o.get("name").equals(name))
            .findAny()
            .orElseThrow();
        return (String) m.get("iss");
    }
}
