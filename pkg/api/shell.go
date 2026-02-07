package api

import "strings"

// ShellQuoteArgs joins command arguments into a single shell-safe string.
// Arguments containing special characters are single-quoted.
func ShellQuoteArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if strings.ContainsAny(arg, " \t\n\"'`$\\!*?[]{}();<>&|") {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		} else {
			quoted[i] = arg
		}
	}
	return strings.Join(quoted, " ")
}
