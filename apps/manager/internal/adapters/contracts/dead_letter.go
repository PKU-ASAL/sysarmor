package contracts

import (
	"encoding/json"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func PermanentMessage(message ports.RawMessage, class string, cause error) error {
	envelope, _ := json.Marshal(map[string]any{
		"source_topic": message.Topic, "source_partition": message.Partition,
		"source_offset": message.Offset, "source_key": message.Key,
		"failure_class": class, "failure_message": cause.Error(),
		"failure_code": class, "payload": message.Value,
	})
	deadLetter := message
	deadLetter.Value = envelope
	return ports.PermanentError{Err: cause, Message: &deadLetter}
}
