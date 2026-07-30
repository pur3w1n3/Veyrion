package com.aq.fixture;

import org.springframework.web.client.RestTemplate;

/**
 * Mirrors app SSRF via Spring RestTemplate (implementation outside classPrefix).
 */
public final class RestTemplateSsrfFixture {
    private RestTemplateSsrfFixture() {
    }

    public static void main(String[] args) {
        RestTemplate client = new RestTemplate();
        client.getForObject("http://127.0.0.1:9/veyrion-ssrf", String.class);
        client.exchange("http://127.0.0.1:9/veyrion-ssrf", "GET", null, String.class);
        System.out.println("RestTemplateSsrfFixture: PASS");
    }
}
