// +build linux

package main

import (
    "os"
    "flag"
    "fmt"
    "time"
    "strconv"
    "strings"
    "syscall"
    "github.com/pkg/errors"
    "github.com/elastic/go-libaudit"
    "github.com/golang/glog"
    "github.com/elastic/go-libaudit/auparse"
)

const (
        auditLocked = 2

        unicast   = "unicast"
        multicast = "multicast"

        lostEventsUpdateInterval        = time.Second * 15
        maxDefaultStreamBufferConsumers = 4

        bsKernel backpressureStrategy = 1 << iota
        bsUserSpace
        bsAuto
)

type backpressureStrategy uint8

func usage() {
	fmt.Fprintf(os.Stderr, "usage: example -stderrthreshold=[INFO|WARN|FATAL] -log_dir=[string]\n", )
	flag.PrintDefaults()
	os.Exit(2)
}

func init() {
	flag.Usage = usage
	flag.Parse()
}

func main() {

    config := defaultConfig

    _, _, kernel, _ := kernelVersion()

    glog.Infof("auditd module is running as euid=%v on kernel=%v", os.Geteuid(), kernel)

    client, err := newAuditClient(&config)

    if err != nil {
        glog.Error("Failed to create new audit client")
	os.Exit(2)
    }

    defer client.Close()

    status, err := client.GetStatus()
    if err != nil {
        glog.Error("failed to get audit status")
        os.Exit(2)
    }

    glog.Infof("received audit status=%+v", status)

    receive(client)

    return
}

func receive(r *libaudit.AuditClient) error {
	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
	}
}

func newAuditClient(c *Config) (*libaudit.AuditClient, error) {
        var err error
        c.SocketType, err = determineSocketType(c)
        if err != nil {
                return nil, err
        }
        glog.Infof("socket_type=%s will be used.", c.SocketType)

        if c.SocketType == multicast {
                return libaudit.NewMulticastAuditClient(nil)
        }
        return libaudit.NewAuditClient(nil)
}

func kernelVersion() (major, minor int, full string, err error) {
        var uname syscall.Utsname
        if err := syscall.Uname(&uname); err != nil {
                return 0, 0, "", err
        }

        length := len(uname.Release)
        data := make([]byte, length)
        for i, v := range uname.Release {
                if v == 0 {
                        length = i
                        break
                }
                data[i] = byte(v)
        }

        release := string(data[:length])
        parts := strings.SplitN(release, ".", 3)
        if len(parts) < 2 {
                return 0, 0, release, errors.Errorf("failed to parse uname release '%v'", release)
        }

        major, err = strconv.Atoi(parts[0])
        if err != nil {
                return 0, 0, release, errors.Wrapf(err, "failed to parse major version from '%v'", release)
        }

        minor, err = strconv.Atoi(parts[1])
        if err != nil {
                return 0, 0, release, errors.Wrapf(err, "failed to parse minor version from '%v'", release)
        }

        return major, minor, release, nil
}

func determineSocketType(c *Config) (string, error) {
        client, err := libaudit.NewAuditClient(nil)
        if err != nil {
                if c.SocketType == "" {
                        return "", errors.Wrap(err, "failed to create audit client")
                }
                // Ignore errors if a socket type has been specified. It will fail during
                // further setup and its necessary for unit tests to pass
                return c.SocketType, nil
        }
        defer client.Close()
        status, err := client.GetStatus()
        if err != nil {
                if c.SocketType == "" {
                        return "", errors.Wrap(err, "failed to get audit status")
                }
                return c.SocketType, nil
        }
        rules := c.rules()

        isLocked := status.Enabled == auditLocked
        hasMulticast := hasMulticastSupport()
        hasRules := len(rules) > 0

        const useAutodetect = "Remove the socket_type option to have auditbeat " +
                "select the most suitable subscription method."
        switch c.SocketType {
        case unicast:
                if isLocked {
                        glog.Errorf("requested unicast socket_type is not available "+
                                "because audit configuration is locked in the kernel "+
                                "(enabled=2). %s", useAutodetect)
                        return "", errors.New("unicast socket_type not available")
                }
                return c.SocketType, nil

        case multicast:
                if hasMulticast {
                        if hasRules {
                                glog.Warning("The audit rules specified in the configuration " +
                                        "cannot be applied when using a multicast socket_type.")
                        }
                        return c.SocketType, nil
                }
                glog.Errorf("socket_type is set to multicast but based on the "+
                        "kernel version, multicast audit subscriptions are not supported. %s",
                        useAutodetect)
                return "", errors.New("multicast socket_type not available")

        default:
                // attempt to determine the optimal socket_type
                if hasMulticast {
                        if hasRules {
                                if isLocked {
                                        glog.Warning("Audit rules specified in the configuration " +
                                                "cannot be applied because the audit rules have been locked " +
                                                "in the kernel (enabled=2). A multicast audit subscription " +
                                                "will be used instead, which does not support setting rules")
                                        return multicast, nil
                                }
                                return unicast, nil
                        }
                        return multicast, nil
                }
                if isLocked {
                        glog.Errorf("Cannot continue: audit configuration is locked " +
                                "in the kernel (enabled=2) which prevents using unicast " +
                                "sockets. Multicast audit subscriptions are not available " +
                                "in this kernel. Disable locking the audit configuration " +
                                "to use auditbeat.")
                        return "", errors.New("no connection to audit available")
                }
                return unicast, nil
        }

}

func getBackpressureStrategy(value string) backpressureStrategy {
        switch value {
        case "kernel":
                return bsKernel
        case "userspace", "user-space":
                return bsUserSpace
        case "auto":
                return bsAuto
        case "both":
                return bsKernel | bsUserSpace
        case "none":
                return 0
        default:
                glog.Warning("Unknown value for the 'backpressure_strategy' option. Using default.")
                fallthrough
        case "", "default":
                return bsAuto
        }
}

func hasMulticastSupport() bool {
        // Check the kernel version because 3.16+ should have multicast
        // support.
        major, minor, _, err := kernelVersion()
        if err != nil {
                // Assume not supported.
                return false
        }

        switch {
        case major > 3,
                major == 3 && minor >= 16:
                return true
        }

        return false
}

