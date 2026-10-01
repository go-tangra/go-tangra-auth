package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// The console list endpoints answer the list contract (go-tangra
// specs/032-server-side-tables, contracts/http-list.md): page, page_size,
// sort and order in, {items,total,page,page_size,sort,order} out. Invalid
// values answer validation_failed (400, this API's status for it, research
// D2) naming the parameter only. Totals count only what the caller may see:
// every list keeps the permission check and tenant scope it had, and the
// count runs under the same filter as the page.
//
// One-release compatibility (research D7): the audit and group-member lists
// keep their cursor path when only cursor/limit are sent (old shape plus
// total); mixing both styles is validation_failed on "cursor". Lists that
// answered a bare array (roles, clients, own sessions) keep answering it to a
// request that names no list parameter at all.

// listParamError answers an invalid list parameter.
func listParamError(w http.ResponseWriter, err error) {
	param := "page"
	var le *listquery.Error
	if errors.As(err, &le) {
		param = le.Param
	}
	WriteDetail(w, ErrValidation, map[string]any{"param": param})
}

// parseList parses the list parameters of r against spec; on failure it has
// answered the request and returns false.
func parseList(w http.ResponseWriter, r *http.Request, spec listquery.Spec) (listquery.Request, bool) {
	req, err := listquery.Parse(r.URL.Query(), spec)
	if err != nil {
		listParamError(w, err)
		return listquery.Request{}, false
	}
	return req, true
}

// hasListParams reports whether q names any list-contract parameter.
func hasListParams(q url.Values) bool {
	return q.Has("page") || q.Has("page_size") || q.Has("sort") || q.Has("order")
}

// windowed sorts a whole, already permission-filtered list in memory and
// returns the requested page of it.
func windowed[T any](items []T, req listquery.Request, key func(T, string) any, tie func(T) string) listquery.Page[T] {
	listquery.SortSlice(items, req, key, tie)
	page, total, applied := listquery.Window(items, req)
	return listquery.NewPage(page, total, applied)
}

// mapPage converts the items of a page, keeping its paging fields.
func mapPage[T, U any](p listquery.Page[T], f func(T) U) listquery.Page[U] {
	items := make([]U, 0, len(p.Items))
	for _, it := range p.Items {
		items = append(items, f(it))
	}
	return listquery.Page[U]{Items: items, Total: p.Total, Page: p.Page, PageSize: p.PageSize, Sort: p.Sort, Order: p.Order}
}
