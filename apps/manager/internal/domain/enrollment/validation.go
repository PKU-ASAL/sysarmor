package enrollment

import (
	"strconv"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func ValidateIdentity(tenantID, agentID string) error {
	if !validIdentityComponent(tenantID) || !validIdentityComponent(agentID) {
		return failure.New(failure.InvalidArgument, "tenant and agent identities are invalid")
	}
	return nil
}

func validIdentityComponent(raw string) bool {
	value := strings.TrimSpace(raw)
	if len(value) == 0 || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !asciiAlphaNumeric(value[index]) && !strings.ContainsRune("._-", rune(value[index])) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func ValidateGateway(address, serverName string) error {
	host, portText, ok := splitGatewayAddress(strings.TrimSpace(address))
	if !ok || strings.TrimSpace(host) == "" {
		return failure.New(failure.InvalidArgument, "gateway address must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return failure.New(failure.InvalidArgument, "gateway port must be between 1 and 65535")
	}
	if strings.ContainsAny(strings.TrimSpace(serverName), ":/\\ \t\r\n") {
		return failure.New(failure.InvalidArgument, "gateway server name must be a host name without a port")
	}
	return nil
}

func splitGatewayAddress(address string) (string, string, bool) {
	separator := strings.LastIndexByte(address, ':')
	if separator <= 0 || separator == len(address)-1 {
		return "", "", false
	}
	host, port := address[:separator], address[separator+1:]
	if strings.HasPrefix(host, "[") {
		return host, port, strings.HasSuffix(host, "]") && len(host) > 2
	}
	return host, port, !strings.ContainsRune(host, ':')
}
