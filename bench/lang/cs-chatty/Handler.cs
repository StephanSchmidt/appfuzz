// appfuzz language test: the n+1 bug from the Rust bench app `chatty`,
// written in C#. Lists all items, then fetches each one again.
using System.Net;
using ItemsAppWorld;
using ItemsAppWorld.wit.Imports.bench.web.v0_1_0;
using static ItemsAppWorld.wit.Imports.bench.web.v0_1_0.ITypesImports;

namespace ItemsAppWorld.wit.Exports.bench.web.v0_1_0;

public class HandlerExportsImpl : IHandlerExports
{
    public static Response Handle(Request req)
    {
        var html = "<ul>";
        foreach (var it in IItemsImports.All())
        {
            try
            {
                var full = IItemsImports.Get(it.id);
                html += $"<li>{WebUtility.HtmlEncode(full.owner)}</li>";
            }
            catch (WitException<string>)
            {
                // not found: skip
            }
        }
        html += "</ul>";
        return new Response(200, html, new List<(string, string)> { ("content-type", "text/html") });
    }
}
