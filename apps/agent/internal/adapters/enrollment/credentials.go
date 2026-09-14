package enrollment

import (
	"fmt"
	"os"
)

func RollbackFailure(paths CredentialPaths, created bool, cause error) error {
	if err := rollbackEnrollmentCredentials(paths, created); err != nil {
		return fmt.Errorf("%w; rollback credentials: %v", cause, err)
	}
	return cause
}

func RemoveCredentials(paths CredentialPaths) []string {
	var failures []string
	for _, path := range []string{paths.CA, paths.Certificate, paths.Key} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	return failures
}

func RemovePendingKey(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
