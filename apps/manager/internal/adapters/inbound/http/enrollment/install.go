package enrollment

import (
	"net/http"
	"strings"

	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) Install(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ticket := strings.TrimSpace(request.URL.Query().Get("ticket"))
	if ticket == "" {
		http.NotFound(writer, request)
		return
	}
	result, err := handler.bootstrap.Redeem(request.Context(), enrollmentapp.RedeemBootstrapCommand{
		TicketHash: hashToken(ticket),
	})
	if err != nil {
		writeInstallError(writer, request, err)
		return
	}
	script, err := handler.install.Render(request, result.Enrollment, result.Token)
	if err != nil {
		http.Error(writer, "render install script", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = writer.Write([]byte(script))
}

func writeInstallError(writer http.ResponseWriter, request *http.Request, err error) {
	switch failure.KindOf(err) {
	case failure.NotFound, failure.Conflict:
		http.NotFound(writer, request)
	case failure.FailedPrecondition:
		http.Error(writer, "enrollment expired", http.StatusGone)
	case failure.InvalidArgument:
		http.Error(writer, "invalid bootstrap ticket", http.StatusBadRequest)
	default:
		http.Error(writer, "redeem bootstrap ticket", http.StatusInternalServerError)
	}
}
