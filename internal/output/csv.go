package output

import (
	"encoding/csv"
	"io"
	"sort"
	"strings"

	"github.com/raxwqx/orbit/internal/dns"
)

// PrintCSV writes one row per DNS, security, or warning value.
func PrintCSV(w io.Writer, result dns.LookupResult) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"target", "record_type", "value"}); err != nil {
		return err
	}
	for _, group := range []struct {
		name   string
		values []string
	}{
		{"A", result.A},
		{"AAAA", result.AAAA},
		{"MX", result.MX},
		{"NS", result.NS},
		{"CNAME", result.CNAME},
		{"TXT", result.TXT},
		{"SPF", result.Security.SPF.Records},
		{"DMARC", result.Security.DMARC.Records},
	} {
		if err := writeCSVValues(writer, result.Target, group.name, group.values); err != nil {
			return err
		}
	}
	if result.Security.DNSSEC.Status != "" {
		value := result.Security.DNSSEC.Status
		if result.Security.DNSSEC.Validated {
			value += " (validated)"
		}
		if err := writeCSVRecord(writer, result.Target, "DNSSEC", value); err != nil {
			return err
		}
	}
	ptrKeys := make([]string, 0, len(result.PTR))
	for address := range result.PTR {
		ptrKeys = append(ptrKeys, address)
	}
	sort.Strings(ptrKeys)
	for _, address := range ptrKeys {
		if err := writeCSVValues(writer, result.Target, "PTR "+address, result.PTR[address]); err != nil {
			return err
		}
	}
	for _, warning := range result.Warnings {
		if err := writeCSVRecord(writer, result.Target, "warning", warning); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func writeCSVRecord(writer *csv.Writer, target, recordType, value string) error {
	return writer.Write([]string{safeCSVCell(target), safeCSVCell(recordType), safeCSVCell(value)})
}

func safeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func writeCSVValues(writer *csv.Writer, target, recordType string, values []string) error {
	rows := append([]string(nil), values...)
	sort.Strings(rows)
	for _, value := range rows {
		if err := writeCSVRecord(writer, target, recordType, value); err != nil {
			return err
		}
	}
	return nil
}
