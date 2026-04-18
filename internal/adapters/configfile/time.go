package configfile

import "time"

func nowStamp() string {
	return time.Now().Format("20060102-150405")
}
