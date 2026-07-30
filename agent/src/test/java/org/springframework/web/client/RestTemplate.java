package org.springframework.web.client;

/** Test stub: Spring RestTemplate SSRF surface. */
public class RestTemplate {
    public String getForObject(String url, Class<?> responseType) {
        return url == null ? "" : url;
    }

    public Object exchange(String url, String method, Object request, Class<?> responseType) {
        return url;
    }
}
