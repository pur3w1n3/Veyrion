package com.aq.jvmsentinel.ai.tool;

import com.aq.jvmsentinel.control.ApiDtos;

import java.util.List;

/** plan_propose / sandbox_probe 所用 entry ref 别名的聚焦验收检查。 */
public final class EntryRefResolverAcceptanceTest {
    public static void main(String[] args) {
        List<ApiDtos.EntryDto> entries = List.of(
                entry("entry-ann-1", "GET", "/blade/a"),
                entry("entry-ann-2", "POST", "/blade/a"),
                entry("entry-ann-3", "GET", "/blade/b"),
                entry("entry-dup-a", "GET", "/shared"),
                entry("entry-dup-b", "GET", "/shared"));

        expectResolved(entries, "entry:entry-ann-1", "entry-ann-1");
        expectResolved(entries, "entry-ann-1", "entry-ann-1");
        expectResolved(entries, "entry:GET:/blade/a", "entry-ann-1");
        expectResolved(entries, "entry:POST:/blade/a", "entry-ann-2");
        expectResolved(entries, "entry:get:/blade/b/", "entry-ann-3");

        check(EntryRefResolver.joinKeys(entries, "entry:entry-ann-1")
                        .contains("entry:GET:/blade/a"),
                "joinKeys adds METHOD:route alias for ann id");
        check(EntryRefResolver.refsEquivalent(entries, "entry:entry-ann-2", "entry:POST:/blade/a"),
                "refsEquivalent ann ↔ METHOD:route");
        check("entry:GET:/blade/b".equals(EntryRefResolver.methodRouteRef(entries.get(2))),
                "methodRouteRef normalizes trailing slash");

        expectCode(entries, "/invented/path", EntryRefResolver.CODE_MUST_BE_ENTRY);
        expectCode(entries, "evidence:entry-ann-1", EntryRefResolver.CODE_MUST_BE_ENTRY);
        expectCode(entries, "entry:", EntryRefResolver.CODE_MUST_BE_ENTRY);
        expectCode(entries, "entry:missing", EntryRefResolver.CODE_NOT_FOUND);
        expectCode(entries, "entry:GET:/missing", EntryRefResolver.CODE_NOT_FOUND);
        expectCode(entries, "entry:GET:/shared", EntryRefResolver.CODE_AMBIGUOUS);

        System.out.println("EntryRefResolverAcceptanceTest: PASS");
    }

    private static void expectResolved(List<ApiDtos.EntryDto> entries, String raw, String expectedId) {
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(entries, raw);
        check(resolution.resolved(), "expected resolve for " + raw);
        check(expectedId.equals(resolution.entry().id()), "id for " + raw);
        check(("entry:" + expectedId).equals(resolution.canonicalRef()), "canonical for " + raw);
    }

    private static void expectCode(List<ApiDtos.EntryDto> entries, String raw, String code) {
        EntryRefResolver.Resolution resolution = EntryRefResolver.resolve(entries, raw);
        check(!resolution.resolved(), "expected unresolved for " + raw);
        check(code.equals(resolution.code()), "code for " + raw + " was " + resolution.code());
    }

    private static ApiDtos.EntryDto entry(String id, String method, String route) {
        return new ApiDtos.EntryDto(ApiDtos.SCHEMA_VERSION, "project-a", "digest-a", "scan-a",
                id, "HTTP", method, route, "demo.Controller", "Controller",
                List.of(), List.of(), ApiDtos.STATIC_INFERRED, 0.5d, 0, List.of());
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
