package com.aq.jvmsentinel.provider.chat;

import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.fasterxml.jackson.databind.JsonNode;

/** 可注入 transport 边界；acceptance test 在此提供受控本地 response。 */
@FunctionalInterface
public interface ChatTransport {
    ProviderChatTransport.Response send(ProviderDefinition provider, byte[] credential,
                                        JsonNode requestBody, ProviderChatTransport.Limits limits);
}
