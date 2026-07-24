package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.fasterxml.jackson.databind.JsonNode;

/** Injectable transport boundary; acceptance tests provide controlled local responses here. */
@FunctionalInterface
public interface ChatTransport {
    ProviderChatTransport.Response send(ProviderDefinition provider, byte[] credential,
                                        JsonNode requestBody, ProviderChatTransport.Limits limits);
}
