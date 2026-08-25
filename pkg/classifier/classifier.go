package classifier

// ClassLabels maps integers to threat class names.
var ClassLabels = map[int]string{
	0: "BENIGN",
	1: "DDOS",
	2: "PORTSCAN",
	3: "BRUTEFORCE",
}

// ClassDescriptions provides details about each classification.
var ClassDescriptions = map[int]string{
	0: "Normal network operations with standard TCP/UDP transactions.",
	1: "Distributed Denial of Service attack characterized by excessive packets and SYN floods.",
	2: "Port Scan scanning multiple destination ports to find open network interfaces.",
	3: "Brute Force authentication attempts, typical on SSH (22) or FTP (21).",
}

// GetDescription returns the description of a threat type.
func GetDescription(classID int) string {
	if desc, ok := ClassDescriptions[classID]; ok {
		return desc
	}
	return "Unknown connection type."
}
